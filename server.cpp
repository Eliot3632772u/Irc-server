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
        serverResponse(client_fd, status::ERR_INPUTTOOLONG); // check
        return ;
    }
    
    this->clients[client_fd].second.buffer += bufferString;

    if (bufferString.size() > 1){

        if ((bufferString[bufferString.size() - 1] == '\n' && bufferString[bufferString.size() - 2] == '\r')){

            if (this->clients[client_fd].second.buffer.size() == 2){

                this->clients[client_fd].second.buffer.erase();
                return ;
            }
            // parse message
			size_t last = this->clients[client_fd].second.buffer.size() - 3;
    		this->clients[client_fd].second.buffer =  this->clients[client_fd].second.buffer.substr(0, last);

			for(int i = 0; i < 	this->clients[client_fd].second.buffer.size(); i++){

				if (this->clients[client_fd].second.buffer[i] == '\r' || this->clients[client_fd].second.buffer[i] == '\n'){

					this->clients[client_fd].second.buffer.clear();
					return;
				}
			}

            parseCmd(client_fd);
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

        prefix = buffer.substr(0, prefixl);

        size_t nick_end = prefix.find_first_of("!@");
        if (nick_end == std::string::npos)
            nick_end = prefix.size();

        this->clients[client_fd].second.prefix = prefix.substr(1, nick_end - 1);

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
        command = buffer.substr(0, commandl);
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

        buffer = buffer.substr(pos);
        
        if (buffer[0] != ':'){
            
           for(pos = 0; pos < buffer.size(); pos++){
            
                if (buffer[pos] == ' ')
                    break;
            }
        
            param = buffer.substr(0, pos);
        
            if (pos + 1 < buffer.size())
                buffer = buffer.substr(pos + 1);
            else
                buffer = ""; 
        }
        else
            param = buffer;

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

void Server::handleMessage(int client_fd)
{
	if (this->clients[client_fd].second.prefix.size() != 0 && this->clients[client_fd].second.prefix != this->clients[client_fd].second.nick)
	{
		serverResponse(client_fd, status::ERR_NOSUCHNICK);
		clearClientData(client_fd);
		return ;
	}

	if (this->clients[client_fd].second.command == "PASS")
        passCMD(client_fd);
	else if (this->clients[client_fd].second.command == "NICK")
        nickCMD(client_fd);
	else if (this->clients[client_fd].second.command == "USER")
        userCMD(client_fd);
	else if (this->clients[client_fd].second.command == "JOIN")
        joinCMD(client_fd);
	else if (this->clients[client_fd].second.command == "PRIVMSG")
        privmsgCMD(client_fd);
	else if (this->clients[client_fd].second.command == "KICK")
        kickCMD(client_fd);
	else if (this->clients[client_fd].second.command == "INVITE")
        inviteCMD(client_fd);
	else if (this->clients[client_fd].second.command == "TOPIC")
        topicCMD(client_fd);
	else if (this->clients[client_fd].second.command == "MODE")
        modeCMD(client_fd);
    else if (this->clients[client_fd].second.command == "BOT")
        botCMD(client_fd);
	else
	{
		serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
		clearClientData(client_fd);
		return ;
	}
}

void Server::botCMD(int client_fd){

    if (this->clients[client_fd].second.is_pass_set)
    {
        serverResponse(client_fd, status::ERR_ALREADYREGISTRED);
        clearClientData(client_fd);
        return ;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
        clearClientData(client_fd);
        return ;
    }

    if (this->clients[client_fd].second.params.front() == "help"){

        std::string help_message =
            GREEN ":irc.server.ma Available commands:\n" RESET
            "\n"
            BLUE "1. PASS <password>\n" RESET
            "\n"
            BLUE "2. NICK <nickname>\n" RESET
            "\n"
            BLUE "3. USER <username> <hostname> <servername> :<realname>\n" RESET
            "\n"
            BLUE "4. JOIN <#channel>\n" RESET
            "\n"
            BLUE "5. PRIVMSG <target> :<message>\n"
            "\n"
            BLUE "6. KICK <#channel> <user> [:reason]\n" RESET
            "\n"
            BLUE "7. INVITE <nickname> <#channel>\n" RESET
            "\n"
            BLUE "8. TOPIC <#channel> [:new topic]\n" RESET
            "\n"
            BLUE "9. MODE <#channel> <flags> [params]\n" RESET
            "\n"
            BLUE "10. BOT {help | time}\n" RESET;

        send(client_fd, help_message.c_str(), help_message.size(), MSG_NOSIGNAL);
        clearClientData(client_fd);
        return;
    }
    else if(this->clients[client_fd].second.params.front() == "time"){

        std::time_t result = std::time(nullptr);
        if (result == -1 || !std::localtime(&result)){

            std::string err = ":irc.server.ma :sorry no time available\r\n";
            send(client_fd, err.c_str(), err.size(), MSG_NOSIGNAL);
            clearClientData(client_fd);
            return;
        }
        std::string res = ":irc.server.ma " + this->clients[client_fd].second.nick + " :Current time is ==> ";
        res += std::asctime(std::localtime(&result));
        if (!res.empty() && res.back() == '\n')
            res.pop_back();
        res += "\r\n";
        send(client_fd, res.c_str(), res.size(), MSG_NOSIGNAL);
        clearClientData(client_fd);
        return;
    }
}

void Server::passCMD(int client_fd)
{
    if (this->clients[client_fd].second.is_pass_set)
    {
        serverResponse(client_fd, status::ERR_ALREADYREGISTRED);
        clearClientData(client_fd);
        return ;
    }
    
    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
        clearClientData(client_fd);
        return ;
    }

    if (this->clients[client_fd].second.params.empty() || this->clients[client_fd].second.params.front() != this->serverPass)
    {
        serverResponse(client_fd, status::ERR_PASSWDMISMATCH);
        clearClientData(client_fd);
        return ;
    }

    this->clients[client_fd].second.is_pass_set = true;
}

std::string toLowerScandi(std::string& str)
{
    std::string lower = str;
    for (size_t i = 0; i < str.size(); i++)
    {
        char& c = str[i];
        if (c >= 'A' && c <= 'Z')
            lower[i] = c + 32;
        else if (c == '[')
            lower[i] = '{';
        else if (c == ']')
            lower[i] = '}';
        else if (c == '\\')
            lower[i] = '|';
        else if (c == '~')
            lower[i] = '^';
    }
    return lower;
}

void Server::nickCMD(int client_fd)
{
    if (this->clients[client_fd].second.is_pass_set == false)
    {
        serverResponse(client_fd, status::ERR_PASSWDMISMATCH);
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, status::ERR_ERRONEUSNICKNAME);
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.empty())
    {
        serverResponse(client_fd, status::ERR_NONICKNAMEGIVEN);
        clearClientData(client_fd);
        return;
    }

    for (size_t i = 0; i < this->clients.size(); i++)
    {
        if (this->clients[i].second.nick == this->clients[client_fd].second.params.front())
        {
            serverResponse(client_fd, status::ERR_NICKNAMEINUSE);
            clearClientData(client_fd);
            return;
        }
    }

    if (this->clients[client_fd].second.params.front().size() > 9)
    {
        serverResponse(client_fd, status::ERR_ERRONEUSNICKNAME);
        clearClientData(client_fd);
        return;
    }

    char& c = this->clients[client_fd].second.params.front()[0];
    if (!std::isalpha(c) && std::string("[]\\`_^{|}").find(c) == std::string::npos)
    {
        serverResponse(client_fd, status::ERR_ERRONEUSNICKNAME);
        clearClientData(client_fd);
        return;
    }

    for (size_t i = 1; i < this->clients[client_fd].second.params.front().size(); i++)
    {
        char& c = this->clients[client_fd].second.params.front()[i];
        if (!std::isalnum(c) && std::string("[]\\`_^{|}").find(c) == std::string::npos)
        {
            serverResponse(client_fd, status::ERR_ERRONEUSNICKNAME);
            clearClientData(client_fd);
            return;
        }
    }
    this->clients[client_fd].second.nick = this->clients[client_fd].second.params.front();

	if (!this->clients[client_fd].second.user.empty())
		this->clients[client_fd].second.authenticated = true;
}

void Server::userCMD(int client_fd)
{
	if (this->clients[client_fd].second.authenticated)
	{
		serverResponse(client_fd, status::ERR_ALREADYREGISTRED);
		clearClientData(client_fd);
		return;	
	}

	if (this->clients[client_fd].second.params.size() != 4)
	{
		serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
		clearClientData(client_fd);
		return;
	}

	if (this->clients[client_fd].second.params.front().size() > 9)
	{
		serverResponse(client_fd, status::ERR_NEEDMOREPARAMS); // check
		clearClientData(client_fd);
		return;
	}

	if (this->clients[client_fd].second.params.front().find('@') != std::string::npos)
	{
		serverResponse(client_fd, status::ERR_NEEDMOREPARAMS); // check
		clearClientData(client_fd);
		return;
	}

	this->clients[client_fd].second.user = this->clients[client_fd].second.params.front();

	if (!this->clients[client_fd].second.nick.empty())
		this->clients[client_fd].second.authenticated = true;
}

void Server::joinCMD(int client_fd)
{

}

void Server::privmsgCMD(int client_fd)
{

}

void Server::kickCMD(int client_fd)
{

}

void Server::inviteCMD(int client_fd)
{

}

void Server::topicCMD(int client_fd)
{

}

void Server::modeCMD(int client_fd)
{

}

