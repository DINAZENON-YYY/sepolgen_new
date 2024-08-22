#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#define BUFFER_SIZE 1024

// 函数声明
void read_write_book_file();
void read_log_file();
void print_to_device();
void bind_tcp_ports(int start_port, int end_port);
void connect_tcp_ports(int remote_port);
void bind_udp_port(int port);
void connect_udp_ports(int start_port, int end_port);

int main() {
    // 读写文件 "book.txt"
    read_write_book_file();

    // 读取系统日志文件
    read_log_file();

    // 打印到设备 "/dev/lp0"
    print_to_device();

    // 绑定 TCP 端口
    bind_tcp_ports(7106, 7110);
    bind_tcp_ports(7201, 7201); // 只绑定 7200

    // 连接到远程 TCP 端口
    connect_tcp_ports(8106);
    connect_tcp_ports(8110);

    // 绑定 UDP 端口
    bind_udp_port(8133);

    // 连接到远程 UDP 端口
    connect_udp_ports(9204, 9206);

    return 0;
}

void read_write_book_file() {
    FILE *file = fopen("book.txt", "r+");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    while (fgets(buffer, BUFFER_SIZE, file)) {
        printf("%s", buffer);
    }

    // 写入一些内容
    fprintf(file, "This is a new line in the book.\n");

    fclose(file);
}

void read_log_file() {
    FILE *file = fopen("/var/log/maillog", "r");
    if (file == NULL) {
        perror("Error opening log file");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    while (fgets(buffer, BUFFER_SIZE, file)) {
        //printf("log file done!\n");
    }
	printf("log file done!\n");
    fclose(file);
}

void read_spool_file() {
    FILE *file = fopen("/var/spool/mail/kevin", "r");
    if (file == NULL) {
        perror("Error opening log file");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    while (fgets(buffer, BUFFER_SIZE, file)) {
        //printf("log file done!\n");
    }
	printf("log file done!\n");
    fclose(file);
}

void print_to_device() {
    const char *device = "/dev/lp0";
    int fd = open(device, O_WRONLY | O_NONBLOCK);
    if (fd == -1) {
        perror("Error opening print device");
        //exit(EXIT_FAILURE);
    }

    const char *message = "Printing to /dev/lp0\n";
    write(fd, message, strlen(message));

    close(fd);
}

void bind_tcp_ports(int start_port, int end_port) {
    for (int i = start_port; i <= end_port; i++) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("Error creating socket");
            continue;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(i);

        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
            perror("Error binding socket");
            close(sockfd);
            continue;
        }

        listen(sockfd, 5);
        printf("Listening on port %d...\n", i);
        close(sockfd);
    }
}

void connect_tcp_ports(int remote_port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Error creating socket");
        //exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(remote_port);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("Error connecting to server");
        close(sockfd);
        //exit(EXIT_FAILURE);
    }

    printf("Connected to TCP port %d\n", remote_port);
    close(sockfd);
}

void bind_udp_port(int port) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Error creating UDP socket");
        //exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("Error binding UDP socket");
        close(sockfd);
        //exit(EXIT_FAILURE);
    }

    printf("Bound to UDP port %d\n", port);
    close(sockfd);
}

void connect_udp_ports(int start_port, int end_port) {
    for (int i = start_port; i <= end_port; i++) {
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            perror("Error creating UDP socket");
            //exit(EXIT_FAILURE);
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(i);
        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
            perror("Error connecting to UDP server");
            close(sockfd);
            //exit(EXIT_FAILURE);
        }

        printf("Connected to UDP port %d\n", i);
        close(sockfd);
    }
}