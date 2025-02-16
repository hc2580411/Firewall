#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#define MAX_REQUEST_SIZE 256
#define MAX_RULE_SIZE 256
#define PORT 8080 // Default port for the server
char requests[MAX_REQUEST_SIZE][MAX_REQUEST_SIZE];
int request_count = 0;
typedef struct FirewallRule
{
    char rule[MAX_RULE_SIZE];
    struct FirewallRule *next;
} FirewallRule;
pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;
FirewallRule *rules_head = NULL;
void send_response(int client_sock, char *message)
{
    send(client_sock, message, strlen(message), 0);
}
bool valid_port_range(char *port)
{
    int port_part_1, port_part_2;
    if (sscanf(port, "%d-%d", &port_part_1, &port_part_2) == 2)
    {
        return (port_part_1 >= 0 && port_part_1 <= 65535 &&
                port_part_2 >= 0 && port_part_2 <= 65535 &&
                port_part_1 <= port_part_2);
    }
    else if (sscanf(port, "%d", &port_part_1) == 1)
    {
        return (port_part_1 >= 0 && port_part_1 <= 65535);
    }
    return false;
}
bool valid_ip_address(char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}
bool is_ip_in_range(char *ip)
{
    char address_begin[16];
    char address_end[16];
    if (sscanf(ip, "%15[^-]-%15s", address_begin, address_end) == 2)
    {
        return valid_ip_address(address_begin) && valid_ip_address(address_end);
    }
    return valid_ip_address(ip);
}
void add_rule(char *rule, int client_sock)
{
    char ip[MAX_RULE_SIZE], port[MAX_RULE_SIZE];
    char response[MAX_REQUEST_SIZE];
    if (sscanf(rule, "%s %s", ip, port) != 2 || !is_ip_in_range(ip) || !valid_port_range(port))
    {
        snprintf(response, sizeof(response), "Invalid rule\n");
        send_response(client_sock, response);
        return;
    }
    FirewallRule *new_rule = (FirewallRule *)malloc(sizeof(FirewallRule));
    if (!new_rule)
    {
        perror("Failed to add rule");
        send_response(client_sock, "Failed to add rule.\n");
        return;
    }
    strncpy(new_rule->rule, rule, MAX_RULE_SIZE);
    new_rule->rule[MAX_RULE_SIZE - 1] = '\0';
    new_rule->next = rules_head;
    rules_head = new_rule;
    snprintf(response, sizeof(response), "Rule added\n");
    send_response(client_sock, response);
}
void delete_rule(char *rule, int client_sock)
{
    char ip[MAX_RULE_SIZE], port[MAX_RULE_SIZE];
    char response[MAX_REQUEST_SIZE];
    FirewallRule *current = rules_head;
    FirewallRule *previous = NULL;
    bool found = false;
    while (current != NULL)
    {
        if (strcmp(current->rule, rule) == 0)
        {
            found = true;
            if (previous == NULL)
            {
                rules_head = current->next;
            }
            else
            {
                previous->next = current->next;
            }
            free(current);
            snprintf(response, sizeof(response), "Rule deleted\n");
            send_response(client_sock, response);
            return;
        }
        previous = current;
        current = current->next;
    }
    if (!found)
    {
        snprintf(response, sizeof(response), "Rule not found\n");
        send_response(client_sock, response);
    }
}
void add_request(char *request, int client_sock)
{
    if (request_count < MAX_REQUEST_SIZE)
    {
        strncpy(requests[request_count], request, MAX_REQUEST_SIZE);
        requests[request_count][MAX_REQUEST_SIZE - 1] = '\0';
        request_count++;
    }
    else
    {
        send_response(client_sock, "Request list is full!\n");
    }
}
void list_requests(int client_sock)
{
    char response[MAX_REQUEST_SIZE * MAX_REQUEST_SIZE];
    response[0] = '\0';
    if (request_count == 0)
    {
        snprintf(response, sizeof(response), "There is no request right now\n");
    }
    else
    {
        snprintf(response, sizeof(response), "Listing all requests:\n");
        for (int i = 0; i < request_count; i++)
        {
            snprintf(response + strlen(response), sizeof(response) - strlen(response), "Request %d: %s\n", i + 1, requests[i]);
        }
    }
    send_response(client_sock, response);
}
void check_rule(char *rule, int client_sock)
{
    char ip[MAX_RULE_SIZE], port[MAX_RULE_SIZE];
    char response[MAX_REQUEST_SIZE];
    if (sscanf(rule, "%s %s", ip, port) != 2 || !is_ip_in_range(ip) || !valid_port_range(port))
    {
        snprintf(response, sizeof(response), "Illegal IP address or port specified\
n");
        send_response(client_sock, response);
        return;
    }
    FirewallRule *current = rules_head;
    bool matched = false;
    while (current != NULL)
    {
        char stored_ip[MAX_RULE_SIZE], stored_port[MAX_RULE_SIZE];
        sscanf(current->rule, "%s %s", stored_ip, stored_port);
        if (strcmp(stored_ip, ip) == 0 && strcmp(stored_port, port) == 0)
        {
            matched = true;
            snprintf(response, sizeof(response), "Connection accepted\n");
            send_response(client_sock, response);
            return;
        }
        current = current->next;
    }
    if (!matched)
    {
        snprintf(response, sizeof(response), "Connection rejected\n");
        send_response(client_sock, response);
    }
}
void list_rules(int client_sock)
{
    char response[MAX_REQUEST_SIZE * MAX_REQUEST_SIZE];
    response[0] = '\0';
    if (rules_head == NULL)
    {
        snprintf(response, sizeof(response), "No firewall rule found.\n");
    }
    else
    {
        snprintf(response, sizeof(response), "Listing all firewall rules:\n");
        FirewallRule *current = rules_head;
        int i = 1;
        while (current != NULL)
        {
            char ip[MAX_RULE_SIZE], port[MAX_RULE_SIZE];
            if (sscanf(current->rule, "%s %s", ip, port) == 2)
            {
                snprintf(response + strlen(response), sizeof(response) - strlen(response), "Rule %d: %s\n", i, current->rule);
                snprintf(response + strlen(response), sizeof(response) - strlen(response), "Query %d: %s %s\n", i, ip, port);
            }
            current = current->next;
            i++;
        }
    }
    send_response(client_sock, response);
}
void *handle_client(void *arg)
{
    int client_sock = *(int *)arg;
    free(arg);
    char input[MAX_REQUEST_SIZE];
    while (recv(client_sock, input, sizeof(input), 0) > 0)
    {
        input[strcspn(input, "\n")] = '\0'; // Remove newline
        char command[MAX_REQUEST_SIZE], args[MAX_REQUEST_SIZE];
        int num_fields = sscanf(input, "%s %[^\n]", command, args);
        pthread_mutex_lock(&rules_mutex);
        if (num_fields < 1)
        {
            send_response(client_sock, "Invalid input\n");
        }
        else
        {
            if (strcmp(command, "R") == 0)
            {
                list_requests(client_sock);
                add_request(input, client_sock);
            }
            else if (strcmp(command, "A") == 0)
            {
                add_rule(args, client_sock);
                add_request(input, client_sock);
            }
            else if (strcmp(command, "D") == 0)
            {
                delete_rule(args, client_sock);
                add_request(input, client_sock);
            }
            else if (strcmp(command, "C") == 0)
            {
                check_rule(args, client_sock);
                add_request(input, client_sock);
            }
            else if (strcmp(command, "L") == 0)
            {
                list_rules(client_sock);
                add_request(input, client_sock);
            }
            else
            {
                send_response(client_sock, "Illegal request\n");
            }
        }
        pthread_mutex_unlock(&rules_mutex);
    }
    close(client_sock);
}
void run_server(int port)
{
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_sock, 3) < 0)
    {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server started on port %d.\n", port);
    while ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr,
                                 &client_len)) >= 0)
    {
        pthread_t thread_id;
        int *new_sock = malloc(sizeof(int));
        *new_sock = client_sock;
        pthread_create(&thread_id, NULL, handle_client, (void *)new_sock);
    }
    if (client_sock < 0)
    {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }
}
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "-i") == 0)
    {
        run_server(PORT);
    }
    else if (argc == 2)
    {
        int port = atoi(argv[1]);
        run_server(port);
    }
    else
    {
        printf("Usage: %s -i or %s <port>\n", argv[0], argv[0]);
        return 1;
    }
    return 0;
}