#include "inc.hpp"
#include "server.hpp"

Server::Server(std::string serverPass, std::string serverPort) : serverPass(serverPass), serverPort(serverPort){}

struct addrinfo * initSocketData(const char * host, const char * port){

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int status = getaddrinfo(host, port, &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(status) << "\n";
        return NULL;
    }

    return res;
}

void initSocketsError(const char * err, int socketFd, struct addrinfo * addrinfo){

    if (addrinfo)
        freeaddrinfo(addrinfo);

    if (err)
        perror(err);

    if (socketFd)
        close(socketFd);

    exit(1);
}

void Server::initSocket(){

    struct addrinfo *res;
    
    res = initSocketData(NULL, this->serverPort.c_str());
    if(res == NULL)
        initSocketsError(NULL, -1, res);
        
    this->socketFd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (this->socketFd == -1)
        initSocketsError("socket: ", -1, res);


    if (fcntl(this->socketFd, F_SETFL, O_NONBLOCK) < 0)
        initSocketsError("fcntl: ", this->socketFd, res);

    int yes = 1;
    if (setsockopt(this->socketFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        initSocketsError("stesocketopt: ", this->socketFd, res);
    

    if (bind(this->socketFd, res->ai_addr, res->ai_addrlen) < 0)
        initSocketsError("bind: ", this->socketFd, res);


    if (listen(this->socketFd, SOMAXCONN) < 0)
        initSocketsError("listen: ", this->socketFd, res);

    freeaddrinfo(res);
}

void Server::creatEpoll(){

    this->epollFd = epoll_create1(0);
    if (this->epollFd < 0)
        initSocketsError("epoll_create: ", this->socketFd, NULL);

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.fd = this->socketFd;

    if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, this->socketFd, &event) == -1) {
           
        close(this->epollFd);
        initSocketsError("epoll_ctl", this->socketFd, NULL);
    }
}

void Server::acceptConnections(){

    struct epoll_event events[100];

    while (true){
        
        int ready_fds = epoll_wait(this->epollFd, events, 100, -1);
        std::cout << "waiting :" << std::endl;
        if (ready_fds < 0){
            
            close(this->epollFd);
            initSocketsError("epoll_event: ", this->socketFd, NULL);
        }

        for(int i = 0; i < ready_fds; i++){

            int fd = events[i].data.fd;

            if (fd == this->socketFd){

                int client_fd = accept(fd, NULL, NULL);
                if (client_fd < 0){

                    close(this->epollFd);
                    initSocketsError("accept: ", this->socketFd, NULL);
                }

                fcntl(client_fd, F_SETFL, O_NONBLOCK);

                struct epoll_event event;
                event.events = EPOLLIN | EPOLLOUT | EPOLLET;
                event.data.fd = client_fd;

                if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, client_fd, &event) == -1) {
                    
                    close(this->epollFd);
                    close(client_fd);
                    for(int i = 0; i < this->clients.size(); i++)
                        close(this->clients[i].first);
                    
                    initSocketsError("epoll_ctl", this->socketFd, NULL);
                }

                this->clients[client_fd].second.client_fd = client_fd;

                continue;
            }
            else {
                
                // parse cmd
                readReq(fd);
            }

        }
    }
}


void Server::readReq(int client_fd){

    char buffer[550] = {0};

    ssize_t read_bytes;
    if ((read_bytes = read(client_fd, buffer, 549)) == -1)
        return ;

    if (read_bytes == 0){

        // delete_client
        close(client_fd);
        this->clients.erase(client_fd);
        return;
    }

    std::string bufferString = buffer;

    if (bufferString.size() + this->clients[client_fd].second.buffer.size() > 512){

        this->clients[client_fd].second.buffer.erase();
        // throw message too long
        serverResponse(client_fd, status::ERR_INPUTTOOLONG);
        return ;
    }
    
    this->clients[client_fd].second.buffer += bufferString;

    if (bufferString.size() > 1){

        if ((bufferString[bufferString.size() - 1] == '\n' || bufferString[bufferString.size() - 2] == '\r')){

            if (this->clients[client_fd].second.buffer.size() == 2){

                this->clients[client_fd].second.buffer.erase();
                return ;
            }
            // parse message
        }
    } 
}

void Server::parseCmd(int client_fd){

    size_t last = this->clients[client_fd].second.buffer.size() - 3;
    std::string buffer =  this->clients[client_fd].second.buffer.substr(0, last);

    if (buffer[0] == ':'){

        std::string prefix;

        size_t prefixl;
        for(prefixl = 0; prefixl < buffer.size(); prefixl++){

            if (buffer[prefixl] == ' ')
                break;
        }

        prefix = buffer.substr(0, prefixl - 1);

        int pos;
        for (int i = 0; i < prefix.size(); i++){

            if (prefix[i] == '!' || prefix[i] == '@'){

                pos = i;
                break;
            }
        }

        this->clients[client_fd].second.prefix = prefix.substr(1, pos - 1);

        if (prefixl + 1 < buffer.size())
            buffer = buffer.substr(prefixl + 1);
        else
            buffer = "";
    }

    std::string command;

    int commandl;
    for(commandl = 0; commandl < buffer.size(); commandl++){

        if (buffer[commandl] == ' ')
            break;
    }

    if (commandl > 0)
        command = buffer.substr(0, commandl - 1);
    else{

        clearClientData(client_fd);
        serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
        return;
    }

    for (int i = 0; i < command.size(); i++){

        if (!isalpha(command[i])){

            // throw not valid command 
            clearClientData(client_fd);
            serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
            return;
        }
    }

    this->clients[client_fd].second.command = command;

    if (commandl + 1 < buffer.size())
        buffer = buffer.substr(commandl + 1);
    else{

        this->clients[client_fd].second.buffer.clear();
        // responde to message
        return;
    }

    while(buffer.size()){

        std::string param;

        size_t pos = buffer.find_first_not_of(' ');

        if (pos == std::string::npos){

            this->clients[client_fd].second.buffer.clear();
            // respond to message
            return ;
        }

        param = buffer.substr(0, pos - 1);

        if (pos + 1 < buffer.size())
            buffer = buffer.substr(pos + 1);
        else
            buffer = "";

        if (param[0] == ':'){

            this->clients[client_fd].second.params.push_back(param.substr(1));
            this->clients[client_fd].second.buffer.clear();
            // responde to message
            return ;
        }

        this->clients[client_fd].second.params.push_back(param);
    }

    if (this->clients[client_fd].second.params.size() > 15){

        serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
        return ;
    }    
}

void Server::serverResponse(int client_fd, enum status status){


}

void Server::clearClientData(int client_fd){

    this->clients[client_fd].second.buffer.clear();
    this->clients[client_fd].second.prefix.clear();
    this->clients[client_fd].second.command.clear();
    this->clients[client_fd].second.params.clear();
}