#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <paths.h>

#define MAX_CMDLINE_LENGTH  1024    /* max cmdline length in a line*/
#define MAX_BUF_SIZE        4096    /* max buffer size */
#define MAX_CMD_ARG_NUM     32      /* max number of single command args */
#define WRITE_END 1     // pipe write end
#define READ_END 0      // pipe read end

/* 
 * 需要大家完成的代码已经用注释`TODO:`标记
 * 可以编辑器搜索找到
 * 使用支持TODO高亮编辑器（如vscode装TODO highlight插件）的同学可以轻松找到要添加内容的地方。
 */

/*  
    int split_string(char* string, char *sep, char** string_clips);

    基于分隔符sep对于string做分割，并去掉头尾的空格

    arguments:      char* string, 输入, 待分割的字符串 
                    char* sep, 输入, 分割符
                    char** string_clips, 输出, 分割好的字符串数组

    return:   分割的段数 
*/

int split_string(char* string, char *sep, char** string_clips) {
    
    char string_dup[MAX_BUF_SIZE];
    string_clips[0] = strtok(string, sep);
    int clip_num=0;     // 用于记录分割后的段数
    
    do {
        char *head, *tail;
        head = string_clips[clip_num];
        tail = head + strlen(string_clips[clip_num]) - 1;
        while(*head == ' ' && head != tail)         //去掉子字符串头尾的空格
            head ++;
        while(*tail == ' ' && tail != head)
            tail --;
        *(tail + 1) = '\0';
        string_clips[clip_num] = head;
        clip_num ++;
    }while(string_clips[clip_num]=strtok(NULL, sep));   // 使用strtok函数继续分割剩余的字符串，获取下一个子字符串
    return clip_num;
}

/*
    执行内置命令
    arguments:
        argc: 输入，命令的参数个数
        argv: 输入，依次代表每个参数，注意第一个参数就是要执行的命令，
        若执行"ls a b c"命令，则argc=4, argv={"ls", "a", "b", "c"}
        fd: 输出，命令输入和输出的文件描述符 (Deprecated)
    return:
        int, 若执行成功返回0，否则返回值非零
*/
int exec_builtin(int argc, char**argv, int *fd) {
    if(argc == 0) {
        return 0;
    }
    /* TODO: 添加和实现内置指令 */
    if (strcmp(argv[0], "cd") == 0) {
        //cd命令
        if (argc == 1) {
            // 如果没有参数，默认切换到用户主目录
            char *home = getenv("HOME");
            if (chdir(home) != 0) {
                perror("cd");
                return -1;
            }
        } else if (argc == 2) {
            // 切换到指定目录
            if (chdir(argv[1]) != 0) {
                perror("cd");
                return -1;
            }
        } else {
            // 参数数量错误
            fprintf(stderr, "cd: too many arguments\n");
            return -1;
        }
    } else if (strcmp(argv[0], "exit") == 0){
        // exit命令
        exit(0);
    } else if(strcmp(argv[0], "kill") == 0){
        // kill命令：发送信号给进程，默认信号为SIGTERM
        if (argc < 2) {
            fprintf(stderr, "Usage: kill pid [signal]\n");
            return -1;
        }
        // 获取进程ID
        pid_t pid;
        if (sscanf(argv[1], "%d", &pid) != 1 || pid <= 0) {
            fprintf(stderr, "kill: invalid PID '%s'\n", argv[1]);
            return -1;
        }
        int signum = SIGTERM; // 默认信号为SIGTERM
        if (argc >= 3) {
            // 如果指定了信号，解析信号
            if (sscanf(argv[2], "%d", &signum) != 1) {
                fprintf(stderr, "kill: invalid signal '%s'\n", argv[2]);
                return -1;
            }
        }
        // 发送信号
        if (kill(pid, signum) != 0) {
            perror("kill");
            return -1;
        }
        return 0;
    } else {
        // 不是内置指令时
        return -1;
    }
    return 0;
}

/*
    从argv中删除重定向符和随后的参数，并打开对应的文件，将文件描述符放在fd数组中。
    运行后，fd[0]读端的文件描述符，fd[1]是写端的文件描述符
    arguments:
        argc: 输入，命令的参数个数
        argv: 输入，依次代表每个参数，注意第一个参数就是要执行的命令，
        若执行"ls a b c"命令，则argc=4, argv={"ls", "a", "b", "c"}
        fd: 输出，命令输入和输出使用的文件描述符
    return:
        int, 返回处理过重定向后命令的参数个数
*/

int process_redirect(int argc, char** argv, int *fd) {
    /* 默认输入输出到命令行，即输入STDIN_FILENO，输出STDOUT_FILENO */
    fd[READ_END] = STDIN_FILENO;
    fd[WRITE_END] = STDOUT_FILENO;
    int i = 0, j = 0;
    while(i < argc) {
        int tfd;
        if(strcmp(argv[i], ">") == 0) {
            //TODO: 打开输出文件从头写入
            tfd = open(argv[i + 1], O_RDWR | O_CREAT | O_TRUNC, 0666);
            if(tfd < 0) {
                printf("open '%s' error: %s\n", argv[i+1], strerror(errno));
            } else {
                //TODO: 输出重定向
                fd[WRITE_END] = tfd;
            }
            i += 2;
        } else if(strcmp(argv[i], ">>") == 0) {
            //TODO: 打开输出文件追加写入
            tfd = open(argv[i + 1], O_RDWR | O_CREAT | O_APPEND, 0666);
            if(tfd < 0) {
                printf("open '%s' error: %s\n", argv[i+1], strerror(errno));
            } else {
                //TODO:输出重定向
                fd[WRITE_END] = tfd;
            }
            i += 2;
        } else if(strcmp(argv[i], "<") == 0) {
            //TODO: 读输入文件
            tfd = open(argv[i + 1], O_RDONLY);
            if(tfd < 0) {
                printf("open '%s' error: %s\n", argv[i+1], strerror(errno));
            } else {
                //TODO:输出重定向
                fd[READ_END] = tfd;
            }
            i += 2;
        } else {
            argv[j++] = argv[i++];  //如果当前参数不是重定向符号，则将其复制到新的参数数组中
        }
    }
    argv[j] = NULL;
    return j;   // 新的argc
}



/*
    在本进程中执行，且执行完毕后结束进程。
    arguments:
        argc: 命令的参数个数
        argv: 依次代表每个参数，注意第一个参数就是要执行的命令，
        若执行"ls a b c"命令，则argc=4, argv={"ls", "a", "b", "c"}
    return:
        int, 若执行成功则不会返回（进程直接结束），否则返回非零
*/
int execute(int argc, char** argv) {
    int fd[2];
    // 默认输入输出到命令行，即输入STDIN_FILENO，输出STDOUT_FILENO 
    fd[READ_END] = STDIN_FILENO;
    fd[WRITE_END] = STDOUT_FILENO;
    // 处理重定向符，如果不做本部分内容，请注释掉process_redirect的调用
    argc = process_redirect(argc, argv, fd);
    if(exec_builtin(argc, argv, fd) == 0) {
        exit(0);
    }
    // 将标准输入输出STDIN_FILENO和STDOUT_FILENO修改为fd对应的文件
    dup2(fd[READ_END], STDIN_FILENO);
    dup2(fd[WRITE_END], STDOUT_FILENO);
    /* TODO:运行命令与结束 */
    execvp(argv[0], argv);
    return 0;
}

int main() {
    /* 输入的命令行 */
    char cmdline[MAX_CMDLINE_LENGTH];

    char *commands[128];
    char *multi_cmd[128];
    int cmd_count;
    while (1) {
        /* TODO: 增加打印当前目录，格式类似"shell:/home/oslab ->"，你需要改下面的printf */
        char path_name[1024];
        getcwd(path_name, sizeof(path_name));
        printf("shell:%s -> ", path_name);
        fflush(stdout);

        fgets(cmdline, 256, stdin);
        strtok(cmdline, "\n");

        /* TODO: 基于";"的多命令执行，请自行选择位置添加 */
        int multi_cmd_num = split_string(cmdline, ";", multi_cmd);
        for(int i = 0; i < multi_cmd_num; i++){
            strcpy(cmdline, multi_cmd[i]);

            /* 由管道操作符'|'分割的命令行各个部分，每个部分是一条命令 */
            /* 拆解命令行 */
            cmd_count = split_string(cmdline, "|", commands);

            if(cmd_count == 0) {
                continue;
            } else if(cmd_count == 1) {     // 没有管道的单一命令
                char *argv[MAX_CMD_ARG_NUM];
                int argc;
                int fd[2];
                /* TODO:处理参数，分出命令名和参数*/
                argc = split_string(cmdline, " ", argv);

                /* 在没有管道时，内建命令直接在主进程中完成，外部命令通过创建子进程完成 */
                if(exec_builtin(argc, argv, fd) == 0) {
                    continue;
                }
                /* TODO:创建子进程，运行命令，等待命令运行结束*/
                pid_t pid = fork();
                if(pid == 0) {
                    if(execute(argc, argv) < 0) {
                        printf("%s : Command not found.\n",argv[0]);
                        exit(0);
                    }
                }
                while(wait(NULL) > 0);

            } else if(cmd_count == 2) {     // 两个命令间的管道
                int pipefd[2];
                int ret = pipe(pipefd);
                if(ret < 0) {
                    printf("pipe error!\n");
                    continue;
                }
                // 子进程1
                int pid = fork();
                if(pid == 0) {  
                    /*TODO:子进程1 将标准输出重定向到管道，注意这里数组的下标被挖空了要补全*/
                    close(pipefd[0]);
                    dup2(pipefd[1], STDOUT_FILENO);
                    close(pipefd[1]);
                    /* 
                        在使用管道时，为了可以并发运行，所以内建命令也在子进程中运行
                        因此我们用了一个封装好的execute函数
                    */
                    char *argv[MAX_CMD_ARG_NUM];

                    int argc = split_string(commands[0], " ", argv);
                    execute(argc, argv);
                    exit(255);
                    
                }
                // 因为在shell的设计中，管道是并发执行的，所以我们不在每个子进程结束后才运行下一个
                // 而是直接创建下一个子进程
                // 子进程2
                pid = fork();
                if(pid == 0) {  
                    /* TODO:子进程2 将标准输入重定向到管道，注意这里数组的下标被挖空了要补全 */
                    close(pipefd[1]);
                    dup2(pipefd[0], STDIN_FILENO);
                    close(pipefd[0]);

                    char *argv[MAX_CMD_ARG_NUM];
                    /* TODO:处理参数，分出命令名和参数，并使用execute运行
                    * 在使用管道时，为了可以并发运行，所以内建命令也在子进程中运行
                    * 因此我们用了一个封装好的execute函数*/
                    int argc = split_string(commands[1], " ", argv);
                    execute(argc, argv);
                    exit(255);
                }
                close(pipefd[WRITE_END]);
                close(pipefd[READ_END]);
                
                while (wait(NULL) > 0);
            } else {    // 选做：三个以上的命令
                int read_fd;    // 上一个管道的读端口（出口）
                for(int i = 0; i < cmd_count; i++) {
                    int pipefd[2];
                    /* TODO:创建管道，n条命令只需要n-1个管道，所以有一次循环中是不用创建管道的*/
                    if(i != cmd_count - 1){
                        int ret = pipe(pipefd);
                        if(ret < 0) {
                            printf("pipe error!\n");
                            continue;
                        }
                    }

                    int pid = fork();
                    if(pid == 0) {
                        /* TODO:除了最后一条命令外，都将标准输出重定向到当前管道入口*/
                        if(i != cmd_count - 1) {
                            close(pipefd[0]);
                            dup2(pipefd[1], STDOUT_FILENO);
                            close(pipefd[1]);
                        }

                        /* TODO:除了第一条命令外，都将标准输入重定向到上一个管道出口*/
                        if(i != 0) {
                            close(pipefd[1]);
                            dup2(read_fd, STDIN_FILENO);
                            close(read_fd);
                            if(i == cmd_count - 1) close(pipefd[0]);
                        }

                        /* TODO:处理参数，分出命令名和参数，并使用execute运行
                        * 在使用管道时，为了可以并发运行，所以内建命令也在子进程中运行
                        * 因此我们用了一个封装好的execute函数*/
                        char *argv[MAX_CMD_ARG_NUM];
                        int argc = split_string(commands[i], " ", argv);
                        execute(argc, argv);
                        exit(255);
                    }
                    /* 父进程除了第一条命令，都需要关闭当前命令用完的上一个管道读端口 
                    * 父进程除了最后一条命令，都需要保存当前命令的管道读端口 
                    * 记得关闭父进程没用的管道写端口*/
                    if(i != 0) close(read_fd);

                    if(i != cmd_count - 1) read_fd = pipefd[0];
                    
                    close(pipefd[1]);
                    // 因为在shell的设计中，管道是并发执行的，所以我们不在每个子进程结束后才运行下一个
                    // 而是直接创建下一个子进程
                }
                // TODO:等待所有子进程结束
                while(wait(NULL) > 0);
            }
        }
    }
}