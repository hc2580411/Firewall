#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#define BUFFER_SIZE 256
void send_command(int sock, const char *input)
{
    char response[BUFFER_SIZE];
    if (send(sock, input, strlen(input), 0) == -1)
    {
        perror("Send failed");
        return;
    }
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);

    if (bytes_received < 0)
    {
        perror("Receive failed");
        return;
    }
    response[bytes_received] = '\0';
    printf("Server response: %s\n", response);
}
int is_valid_command(const char *command)
{
    return strcmp(command, "A") == 0 || strcmp(command, "D") == 0 ||
           strcmp(command, "L") == 0 || strcmp(command, "R") == 0 ||
           strcmp(command, "C") == 0;
}
int resolve_host(const char *host, struct sockaddr_in *addr)
{
    if (strcmp(host, "localhost") == 0)
    {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        return 1;
    }
    return inet_pton(AF_INET, host, &(addr->sin_addr)) == 1;
}
int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <serverHost> <serverPort> <command> <args>\n",
                argv[0]);
        return 1;
    }
    char *server_host = argv[1];
    int server_port = atoi(argv[2]);
    if (server_port <= 0 || server_port > 65535)
    {
    fprintf(stderr, "Invalid port number. Please enter a port number between 1
    and 65535.\n");
return 1;
    }
    char *command = argv[3];
    if (!is_valid_command(command))
    {
        fprintf(stderr, "Invalid command. Valid commands are: A, D, L, R, C\n");
        return 1;
    }
    int sock;
    struct sockaddr_in server_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation failed");
        return 1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (!resolve_host(server_host, &server_addr))
    {
        perror("Invalid address or address not supported");
        close(sock);
        return 1;
    }
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        close(sock);
        return 1;
    }
    printf("Connected to server %s on port %d.\n", server_host, server_port);
    char input[BUFFER_SIZE];
    input[0] = '\0';
    snprintf(input, sizeof(input), "%s", command);
    for (int i = 4; i < argc; i++)
    {
        strncat(input, " ", sizeof(input) - strlen(input) - 1);
        strncat(input, argv[i], sizeof(input) - strlen(input) - 1);
    }
    send_command(sock, input);
    while (1)
    {
        printf("> ");
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("Error reading input.\n");
            continue;
        }
        input[strcspn(input, "\n")] = '\0';
        if (strcmp(input, "exit") == 0)
        {
            printf("Exiting client.\n");
            break;
        }
        char *command = strtok(input, " ");
        if (!is_valid_command(command))
        {
            printf("Invalid command. Valid commands are: A, D, L, R, C\n");
            continue;
        }
        send_command(sock, input);
    }
    close(sock);
    return 0;
}