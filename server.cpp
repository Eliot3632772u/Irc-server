#include "inc.hpp"
#include "server.hpp"

Server::Server(std::string serverPass, std::string serverPort) : serverPass(serverPass), serverPort(serverPort) {}

struct addrinfo *initSocketData(const char *host, const char *port)
{

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int status = getaddrinfo(host, port, &hints, &res);
    if (status != 0)
    {
        std::cerr << "getaddrinfo: " << gai_strerror(status) << "\n";
        return NULL;
    }

    return res;
}

void initSocketsError(const char *err, int socketFd, struct addrinfo *addrinfo)
{

    if (addrinfo)
        freeaddrinfo(addrinfo);

    if (err)
        perror(err);

    if (socketFd)
        close(socketFd);

    exit(1);
}

void Server::initSocket()
{

    struct addrinfo *res;

    res = initSocketData(NULL, this->serverPort.c_str());
    if (res == NULL)
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

void Server::creatEpoll()
{

    // this->epollFd = epoll_create1(0);
    // if (this->epollFd < 0)
    //     initSocketsError("epoll_create: ", this->socketFd, NULL);

    // struct epoll_event event;
    // event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    // event.data.fd = this->socketFd;

    // if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, this->socketFd, &event) == -1)
    // {

    //     close(this->epollFd);
    //     initSocketsError("epoll_ctl", this->socketFd, NULL);
    // }

    
        this->kqueueFd = kqueue();
        if (this->kqueueFd == -1)
            initSocketsError("kqueue: ", this->socketFd, NULL);

        struct kevent changes[1];

        EV_SET(&changes[0], this->socketFd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
        // EV_SET(&changes[1], this->socketFd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);

        if (kevent(this->kqueueFd, changes, 1, NULL, 0, NULL) == -1) {

            close(this->kqueueFd);
            initSocketsError("kevent ", this->socketFd, NULL);
        }
    
}

void Server::acceptConnections()
{

    // struct epoll_event events[100];
    struct kevent events[100];

    while (true)
    {

        std::cout << YELLOW "Waiting for events..." RESET << std::endl;
        // int ready_fds = epoll_wait(this->epollFd, events, 100, -1);
        int ready_fds = kevent(this->kqueueFd, NULL, 0, events, 100, NULL);
        if (ready_fds < 0)
        {

            close(this->epollFd);
            // initSocketsError("epoll_event: ", this->socketFd, NULL);
            initSocketsError("kevent: ", this->socketFd, NULL);
        }

        for (int i = 0; i < ready_fds; i++)
        {
            // int fd = events[i].data.fd;
            int fd = events[i].ident;
            
            if (fd == this->socketFd)
            {

                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int client_fd = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
                // int client_fd = accept(fd, NULL, NULL);
                if (client_fd < 0)
                {

                    close(this->epollFd);
                    initSocketsError("accept: ", this->socketFd, NULL);
                }

                fcntl(client_fd, F_SETFL, O_NONBLOCK);

                // struct epoll_event event;
                // event.events = EPOLLIN | EPOLLOUT | EPOLLET;
                // event.data.fd = client_fd;
                struct kevent events[1];
                EV_SET(&events[0], client_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
                // EV_SET(&events[1], client_fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);

                if (kevent(this->kqueueFd, events, 1, NULL, 0, NULL) == -1) {
                    perror("kevent client add");
                    close(client_fd);
                    continue;
                }

                // if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, client_fd, &event) == -1)
                // {

                //     close(this->epollFd);
                //     close(client_fd);
                //     for (size_t i = 0; i < this->clients.size(); i++)
                //         close(this->clients[i].first);

                //     initSocketsError("epoll_ctl", this->socketFd, NULL);
                // }

                std::cout << GREEN "Client <" << client_fd << "> just connected" RESET << std::endl;

                this->clients[client_fd].second.client_fd = client_fd;

                this->clients[client_fd].second.host = inet_ntoa(client_addr.sin_addr);

                continue;
            }
            else
            {
                // check this->events[i].filter == EVFILT_WRITE | EVFILT_READ if ready for write and read if not return 
                if (events[i].filter == EVFILT_READ) {
                    readReq(fd);  // handle readable socket
                }
            }
        }
    }
}

void Server::readReq(int client_fd)
{

    char buffer[550] = {0};

    ssize_t read_bytes;
    if ((read_bytes = read(client_fd, buffer, 549)) == -1)
    {
        return;
    }

    
    if (read_bytes == 0)
    {
        // delete_client
        std::cout << RED "Client <" << client_fd << "> just disconnected" RESET << std::endl;
        close(client_fd);
        this->clients.erase(client_fd);
        return;
    }

    std::string bufferString = buffer;


    if (bufferString.size() + this->clients[client_fd].second.buffer.size() > 512)
    {

        this->clients[client_fd].second.buffer.erase();
        serverResponse(client_fd, ERR_UNKNOWNCOMMAND, RED, "INTPUTTOOLONG "); // here changed it from INPUTTOOLONG
        return;
    }

    this->clients[client_fd].second.buffer += bufferString;

    if (bufferString.size() > 1)
    {
        
        if ((bufferString[bufferString.size() - 1] == '\n' && bufferString[bufferString.size() - 2] == '\r'))
        {

            if (this->clients[client_fd].second.buffer.size() == 2)
            {

                this->clients[client_fd].second.buffer.erase();
                return;
            }

            // check if there is /r /n in message
            size_t last = this->clients[client_fd].second.buffer.size() - 2;
            this->clients[client_fd].second.buffer = this->clients[client_fd].second.buffer.substr(0, last);

            for (size_t i = 0; i < this->clients[client_fd].second.buffer.size(); i++)
            {

                // if (this->clients[client_fd].second.buffer[i] == '\r' || this->clients[client_fd].second.buffer[i] == '\0' || this->clients[client_fd].second.buffer[i] == '\n')
                if (this->clients[client_fd].second.buffer[i] < 32 || this->clients[client_fd].second.buffer[i] > 126)
                {
                    std::cout << "stop" << std::endl;
                    this->clients[client_fd].second.buffer.clear();
                    return;
                }
            }
            std::cout << YELLOW << this->clients[client_fd].second.buffer << " " << client_fd << RESET << std::endl;
            parseCmd(client_fd);

        }
    }

}

void Server::parseCmd(int client_fd)
{
    std::string buffer =  this->clients[client_fd].second.buffer;

    if (buffer[0] == ':')
    {

        std::string prefix;

        size_t prefixl;
        for (prefixl = 0; prefixl < buffer.size(); prefixl++)
        {

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

    size_t commandl;
    for (commandl = 0; commandl < buffer.size(); commandl++)
    {

        if (buffer[commandl] == ' ')
            break;
    }

    if (commandl > 0)
        command = buffer.substr(0, commandl);
    else{

        
        clearClientData(client_fd);
        serverResponse(client_fd, ERR_UNKNOWNCOMMAND, RED, command + " ");
        return;
    }
    
    for (size_t i = 0; i < command.size(); i++)
    {
        
        if (!isalpha(command[i]))
        {
            clearClientData(client_fd);
            serverResponse(client_fd, ERR_UNKNOWNCOMMAND, RED, command + " ");
            return;
        }
    }
    
    this->clients[client_fd].second.command = command;
    
    if (commandl + 1 < buffer.size()){

        buffer = buffer.substr(commandl + 1);
    }
    // else
    // {
    //     this->clients[client_fd].second.buffer.clear();
    //     // serverResponse(client_fd, ERR_NEEDMOREPARAMS);
    //     // std::cout << "No params parse" << std::endl;
    //     // no parameters error
    //     // return;
    // }

    while (buffer.size())
    {

        std::string param;

        size_t pos = buffer.find_first_not_of(' ');

        if (pos == std::string::npos)
        {
            this->clients[client_fd].second.buffer.clear();
            break;
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

        if (param[0] == ':')
        {

            this->clients[client_fd].second.params.push_back(param.substr(1));
            this->clients[client_fd].second.buffer.clear();
            break;
        }

        this->clients[client_fd].second.params.push_back(param);
    }

    if (this->clients[client_fd].second.params.size() > 15 || this->clients[client_fd].second.params.size() == 0)
    {

        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, command + " ");
        return;
    }

    handleMessage(client_fd);
    clearClientData(client_fd);
}

void Server::clearClientData(int client_fd)
{

    this->clients[client_fd].second.buffer.clear();
    this->clients[client_fd].second.prefix.clear();
    this->clients[client_fd].second.command.clear();
    this->clients[client_fd].second.params.clear();
}

void Server::serverResponse(int client_fd, enum status code, std::string color, std::string msg)
{
    msg.insert(0, color + ":irc.server.ma ");
    if (ERR_ERRONEUSNICKNAME == code)
        msg += "432 :Erroneous nickname\r\n" RESET;
    else if (ERR_UNKNOWNCOMMAND == code)
        msg += "421 :Unknown command\r\n" RESET;
    else if (ERR_NOSUCHNICK == code)
        msg += "401 :No such nick/channel\r\n" RESET;
    else if (ERR_ALREADYREGISTRED == code)
        msg += "462 :Unauthorized command (already registered)\r\n" RESET;
    else if (ERR_NEEDMOREPARAMS == code)
        msg += "461 :Not enough parameters\r\n" RESET;
    else if (ERR_PASSWDMISMATCH == code)
        msg += "464 :Password incorrect\r\n" RESET;
    else if (ERR_NOTREGISTERED == code)
        msg += "451 :You have not registered\r\n" RESET;
    else if (ERR_ERRONEUSNICKNAME == code)
        msg += "432 :Erroneous nickname\r\n" RESET;
    else if (ERR_NONICKNAMEGIVEN == code)
        msg += "431 :No nickname given\r\n" RESET;
    else if (ERR_NICKNAMEINUSE == code)
        msg += "433 :Nickname is already in use\r\n" RESET;
    else if (ERR_BADCHANNELKEY == code)
        msg += "475 :Cannot join channel (+k)\r\n" RESET;
    else if (ERR_INVITEONLYCHAN == code)
        msg += "473 :Cannot join channel (+i)\r\n" RESET;
    else if (ERR_CHANNELISFULL == code)
        msg += "471 :Cannot join channel (+l)\r\n" RESET;
    else if (ERR_NOSUCHCHANNEL == code)
        msg += "403 :No such channel\r\n" RESET;
    else if (ERR_NORECIPIENT == code)
        msg += "\r\n" RESET;
    else if (ERR_NOTEXTTOSEND == code)
        msg += "412 :No text to send\r\n" RESET;
    else if (ERR_CHANOPRIVSNEEDED == code)
        msg += "482 :You're not channel operator\r\n" RESET;
    else if (ERR_NOTONCHANNEL == code)
        msg += "442 :You're not on that channel\r\n" RESET;
    else if (ERR_USERONCHANNEL == code)
        msg += "443 :is already on channel\r\n" RESET;
    else if (ERR_USERNOTINCHANNEL == code)
        msg += "441 :They aren't on that channel\r\n" RESET;
    else if (ERR_UNKNOWNMODE == code)
        msg += "\r\n" RESET;
    else if (RPL_WELCOME == code)
        msg += "\r\n" RESET ;
    else if (RPL_NOTOPIC == code)
        msg += "331 :No topic is set\r\n" RESET;
    else if (RPL_TOPIC == code)
        msg += "\r\n" RESET;
    else if (ERR_KEYSET == code)
        msg += "467 :Channel key already set\r\n" RESET;
    else if (RPL_INVITING == code)
        msg += "\r\n" RESET;
    
    send(client_fd, msg.c_str(), msg.size(), MSG_NOSIGNAL);
}

std::string toLowerScandi(std::string &str)
{
    std::string lower = str;
    for (size_t i = 0; i < str.size(); i++)
    {
        char &c = str[i];
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

bool areEqualScandi(const std::string& one, const std::string& two)
{
    if (one.length() != two.length())
        return false;
    
    for (size_t i = 0; i < one.length(); i++)
    {
        char c1 = one[i];
        char c2 = two[i];
        
        if (c1 >= 'A' && c1 <= 'Z')
            c1 += 32;
        else if (c1 == '[')
            c1 = '{';
        else if (c1 == ']')
            c1 = '}';
        else if (c1 == '\\')
            c1 = '|';
        else if (c1 == '~')
            c1 = '^';

        if (c2 >= 'A' && c2 <= 'Z')
            c2 += 32;
        else if (c2 == '[')
            c2 = '{';
        else if (c2 == ']')
            c2 = '}';
        else if (c2 == '\\')
            c2 = '|';
        else if (c2 == '~')
            c2 = '^';
        
        if (c1 != c2)
            return false;
    }

    return true;
}

bool validChanName(std::string& name)
{
    if (name.empty() || name.size() > 50)
        return false;

    char& first = name[0];
    if (first != '#' && first != '&')
        return false;

    for (size_t i = 1; i < name.size(); i++)
    {
        char& c = name[i];
        if (c == 0x00 || c == 0x07 || c == 0x0A || c == 0x0D || c == ' ' || c == ',' || c == ':')
            return false;
    }
    return true;
}

void Server::botCMD(int client_fd){

    if (this->clients[client_fd].second.params.size() != 1)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, this->clients[client_fd].second.command + " ");
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
            BLUE "10. BOT {help | time}" RESET "\r\n";

        send(client_fd, help_message.c_str(), help_message.size(), MSG_NOSIGNAL);
        clearClientData(client_fd);
        return;
    }
    else if(this->clients[client_fd].second.params.front() == "time"){

        std::time_t result = std::time(NULL); // use of nullptr changed to NULL
        if (result == -1 || !std::localtime(&result)){

            std::string err = ":irc.server.ma :sorry no time available\r\n";
            send(client_fd, err.c_str(), err.size(), MSG_NOSIGNAL);
            clearClientData(client_fd);
            return;
        }
        std::string res = ORANGE ":irc.server.ma " + this->clients[client_fd].second.nick + " :Current time is ==> ";
        res += std::asctime(std::localtime(&result));
        if (!res.empty() && res[res.size() - 1] == '\n')
            res.erase(res.size() - 1);
        res += "\r\n" RESET;
        send(client_fd, res.c_str(), res.size(), MSG_NOSIGNAL);
        clearClientData(client_fd);
        return;
    }
}

void Server::handleMessage(int client_fd)
{
    std::string & command = this->clients[client_fd].second.command;
    if (this->clients[client_fd].second.prefix.size() != 0 && this->clients[client_fd].second.prefix != this->clients[client_fd].second.nick)
    {
        serverResponse(client_fd, ERR_NOSUCHNICK, RED, this->clients[client_fd].second.nick);
        clearClientData(client_fd);
        return;
    }
    if (this->clients[client_fd].second.command == "PASS")
    {
        passCMD(client_fd);
    }
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
		serverResponse(client_fd, ERR_UNKNOWNCOMMAND, RED, command + " ");
		clearClientData(client_fd);
		return ;
    }
}

void Server::passCMD(int client_fd)
{
    if (this->clients[client_fd].second.is_pass_set)
    {
        serverResponse(client_fd, ERR_ALREADYREGISTRED, RED, "");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, this->clients[client_fd].second.command + " ");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.empty() || this->clients[client_fd].second.params.front() != this->serverPass)
    {
        serverResponse(client_fd, ERR_PASSWDMISMATCH, RED, "");
        clearClientData(client_fd);
        return;
    }

    this->clients[client_fd].second.is_pass_set = true;


    // to remove
    std::cout << "------pass done-----" << std::endl;
}

void Server::nickCMD(int client_fd)
{
    if (this->clients[client_fd].second.is_pass_set == false)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, RED, "");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, ERR_ERRONEUSNICKNAME, RED, this->clients[client_fd].second.nick + " ");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.empty())
    {
        serverResponse(client_fd, ERR_NONICKNAMEGIVEN, RED, "");
        clearClientData(client_fd);
        return;
    }

    for (size_t i = 0; i < this->clients.size(); i++)
    {
        if (this->clients[i].second.nick == this->clients[client_fd].second.params.front())
        {
            serverResponse(client_fd, ERR_NICKNAMEINUSE, RED, this->clients[client_fd].second.nick + " ");
            clearClientData(client_fd);
            return;
        }
    }

    if (this->clients[client_fd].second.params.front().size() > 9)
    {
        serverResponse(client_fd, ERR_ERRONEUSNICKNAME, RED, this->clients[client_fd].second.nick + " ");
        clearClientData(client_fd);
        return;
    }

    char &c = this->clients[client_fd].second.params.front()[0];
    if (!std::isalpha(c) && std::string("[]\\`_^{|}").find(c) == std::string::npos)
    {
        serverResponse(client_fd, ERR_ERRONEUSNICKNAME, RED, this->clients[client_fd].second.nick + " ");
        clearClientData(client_fd);
        return;
    }

    for (size_t i = 1; i < this->clients[client_fd].second.params.front().size(); i++)
    {
        char &c = this->clients[client_fd].second.params.front()[i];
        if (!std::isalnum(c) && std::string("[]\\`_^{|}-").find(c) == std::string::npos)
        {
            serverResponse(client_fd, ERR_ERRONEUSNICKNAME, RED, this->clients[client_fd].second.nick + " ");
            clearClientData(client_fd);
            return;
        }
    }

    this->clients[client_fd].second.nick = this->clients[client_fd].second.params.front();

    if (!this->clients[client_fd].second.user.empty())
    {
        // <nick>!<user>@<host>
        std::string full = this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host;
        serverResponse(client_fd, RPL_WELCOME, GREEN, "001 " + this->clients[client_fd].second.nick + ":Welcome to the Internet Relay Network " + full);
        this->clients[client_fd].second.authenticated = true;
    }


    // to remove
    std::cout << "------nickname done------" << std::endl;
}

void Server::userCMD(int client_fd)
{
    if (this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_ALREADYREGISTRED, RED, "");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.size() != 4)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "USER ");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.front().size() > 9)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "USER ");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.front().find('@') != std::string::npos) // not necessary
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "USER ");
        clearClientData(client_fd);
        return;
    }

    this->clients[client_fd].second.user = this->clients[client_fd].second.params.front();

    if (!this->clients[client_fd].second.nick.empty())
    {
        // <nick>!<user>@<host>
        std::string full = this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host;
        serverResponse(client_fd, RPL_WELCOME, GREEN, "001 " + this->clients[client_fd].second.nick + " :Welcome to the Internet Relay Network " + full);
        this->clients[client_fd].second.authenticated = true;
    }

    std::cout << "------- USER DONE ---------" << std::endl;
}

void Server::joinCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, RED, "");
        return;
    }

    if (this->clients[client_fd].second.params.empty() || this->clients[client_fd].second.params.size() > 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "JOIN ");
        return;
    }

    if (this->clients[client_fd].second.params.size() == 1 && this->clients[client_fd].second.params[0] == "0")
    {
        std::vector<std::string> chans_to_leave = this->clients[client_fd].second.channels;

        for (size_t i = 0; i < chans_to_leave.size(); i++)
        {
            Channel& channel = this->channels[chans_to_leave[i]];

            for (size_t j = 0; j < channel.members.size(); j++)
            {
                if (areEqualScandi(this->clients[client_fd].second.nick, channel.members[j]))
                {
                    std::string message = ":" + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " PART " + channel.name + ": Goodbye!";
                    channel.broadcastToAll(this->clients, this->clients[client_fd].second, message, true);
                    channel.members.erase(channel.members.begin() + j);
                    break;
                }
            }

            for (size_t j = 0; j < channel.operators.size(); j++)
            {
                if (areEqualScandi(this->clients[client_fd].second.nick, channel.operators[j]))
                {
                    std::string message = ":" + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " PART " + channel.name + ": Goodbye!";
                    channel.broadcastToAll(this->clients, this->clients[client_fd].second, message, true);
                    channel.operators.erase(channel.operators.begin() + j);
                    break;
                }
            }
        }
        this->clients[client_fd].second.channels.clear();
        return;
    }


    std::string channels = this->clients[client_fd].second.params[0];
    std::string keys = (this->clients[client_fd].second.params.size() > 1) ? this->clients[client_fd].second.params[1] : "";
    
    std::stringstream ssChans(channels);
    std::stringstream ssKeys(keys);

    std::string key;
    std::string chan;
    std::vector<std::string> keys_vec;
    std::vector<std::string> chans_vec;

    while (std::getline(ssChans, chan, ','))
    {
        chans_vec.push_back(chan);
        if (std::getline(ssKeys, key, ','))
        {
            keys_vec.push_back(key);
        }
        else
        {
            keys_vec.push_back("");
        }
    }

    for (size_t i = 0; i < chans_vec.size(); i++)
    {
        std::string name = chans_vec[i];
        if (!validChanName(name))
        {
            serverResponse(client_fd, ERR_NOSUCHCHANNEL, RED, name + " ");
        }
        else if (this->channels.count(name) > 0)
        {
            if (!this->clients[client_fd].second.hasChannel(name))
            {
                if (!this->channels[name].password.empty() && this->channels[name].password != keys_vec[i])
                {
                    serverResponse(client_fd, ERR_BADCHANNELKEY, RED, name + " ");
                    continue;
                }
                else if (this->channels[name].userlimited && this->channels[name].members.size() + this->channels[name].operators.size() >= this->channels[name].max_users)
                {
                    serverResponse(client_fd, ERR_CHANNELISFULL, RED, name + " ");
                }
                else if (this->channels[name].invite_only)
                {
                    bool was_able_to_join = false;
                    for (size_t i = 0; i < this->channels[name].invited_users.size(); i++)
                    {
                        if (areEqualScandi(this->channels[name].invited_users[i], this->clients[client_fd].second.nick))
                        {
                            this->channels[name].invited_users.erase(this->channels[name].invited_users.begin() + i);
                            this->channels[name].members.push_back(this->clients[client_fd].second.nick);
                            this->clients[client_fd].second.channels.push_back(name);
                            was_able_to_join = true;
                            std::string message = BLUE ":" + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " JOIN :" + name;
                            this->channels[name].broadcastToAll(this->clients, this->clients[client_fd].second, message, true);

                            break;
                        }
                    }
                    if (!was_able_to_join)
                    {
                        serverResponse(client_fd, ERR_INVITEONLYCHAN, RED, name + " ");
                    }
                }
                else
                {
                    this->channels[name].members.push_back(this->clients[client_fd].second.nick);
                    this->clients[client_fd].second.channels.push_back(name);

                    std::string message = BLUE ":" + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " JOIN :" + name;
                    this->channels[name].broadcastToAll(this->clients, this->clients[client_fd].second, message, true);
                }
            }
        }
        else
        {
            Channel new_chan;
            new_chan.name = name;
            new_chan.operators.push_back(this->clients[client_fd].second.nick);

            this->clients[client_fd].second.channels.push_back(name);

            this->channels[name] = new_chan;
            
            std::string message = BLUE ":" + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " JOIN :" + name;
            this->channels[name].broadcastToAll(this->clients, this->clients[client_fd].second, message, true);
        }
    }
}

void Server::privmsgCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, RED, "");
        return;
    }
    if (this->clients[client_fd].second.params.empty())
    {
        serverResponse(client_fd, ERR_NORECIPIENT, RED, "411 :No recipient given PRIVMSG");
        return;
    }
    if (this->clients[client_fd].second.params.size() == 1)
    {
        serverResponse(client_fd, ERR_NOTEXTTOSEND, RED, "");
        return;
    }

    std::string target;
    std::vector<std::string> users;
    std::vector<std::string> channels;
    std::stringstream ss(this->clients[client_fd].second.params[0]);
    
    while (std::getline(ss, target, ','))
    {
        if (validChanName(target))
        {
            channels.push_back(target);
        }
        else if (target != this->clients[client_fd].second.nick)
        {
            users.push_back(target);
        }
    }
    std::string colors[] = {PURPLE, CYAN, ORANGE};
    std::string message = this->clients[client_fd].second.params[1] + "\r\n";
    for (size_t i = 0; i < users.size(); i++)
    {
        bool sent = false;
        std::string& target = users[i];
        std::map<int, std::pair<int, Client> >::iterator it = this->clients.begin();
        size_t j = 0;
        while (it != this->clients.end())
        {

            std::string& connected = it->second.second.nick;
            if (areEqualScandi(target, connected))
            {
                std::string current = colors[j % 3] + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.nick + "@irc.server.ma PRIVMSG " + target + RESET " :" + message;
                send(it->second.second.client_fd, current.c_str(), current.size(), MSG_NOSIGNAL);
                sent = true; 
            }
            it++;
            j++;
        }
        if (!sent)
        {
            serverResponse(client_fd, ERR_NOSUCHNICK, RED, this->clients[client_fd].second.nick + " ");
        }
    }

    for (size_t i = 0; i < channels.size(); i++)
    {
        std::string& target = channels[i];
        if (this->channels.count(channels[i]) > 0 && this->channels[channels[i]].isAnyMember(this->clients[client_fd].second.nick))
        {
            std::string info = colors[std::rand() % 3] + ":" + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@irc.server.ma PRIVMSG " + target + RESET + " :";
            this->channels[target].broadcastToAll(this->clients, this->clients[client_fd].second, info + message, false);
        }
        else
        {
            serverResponse(client_fd, ERR_NOSUCHCHANNEL, RED, target + " ");
        }
    }
}

void Server::kickCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, RED, ":You have not registered");
        return;
    }
    if (this->clients[client_fd].second.params.size() < 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "KICK ");
        return;
    }

    std::string channel = this->clients[client_fd].second.params[0];
    std::string targetNick = this->clients[client_fd].second.params[1];
    
    if (this->channels.count(channel) == 0)
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL, RED, channel + " ");
        return;
    }
    
    bool IsOperator = false;
    std::string operatorNick = this->clients[client_fd].second.nick;
    for (size_t i = 0; i < this->channels[channel].operators.size(); i++)
    {
        if (areEqualScandi(operatorNick, this->channels[channel].operators[i]))
        {
            IsOperator = true;
        }
    }
    if (!IsOperator)
    {
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED, RED, channel + " ");
        return;
    }

    Channel& chan = this->channels[channel];
    if (!chan.isAnyMember(targetNick))
    {
        serverResponse(client_fd, ERR_NOTONCHANNEL, RED, channel + " ");
        return;
    }
    
    std::map<int, std::pair<int, Client> >::iterator it = this->clients.begin();
    while (it != this->clients.end())
    {
        if (areEqualScandi(it->second.second.nick, targetNick))
        {
            it->second.second.removeChannel(chan.name);
        }
        it++;
    }
    
    std::string message = ":" + operatorNick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " KICK " + channel + " " + targetNick;
    message += (this->clients[client_fd].second.params.size() > 2? this->clients[client_fd].second.params[2] : "");
    chan.broadcastToAll(this->clients, this->clients[client_fd].second, message, true);

    chan.removeMember(targetNick);
}

void Server::sendMessageByNick(std::string nick, std::string message)
{
    std::map<int, std::pair<int, Client> >::iterator  it = this->clients.begin();
    while (it != this->clients.end())
    {
        if (it->second.second.nick == nick)
        {
            send(it->second.second.client_fd, message.c_str(), message.size(), MSG_NOSIGNAL);
        }
        it++;
    }
}

void Server::inviteCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, RED, "");
        return;
    }
    if (this->clients[client_fd].second.params.size() < 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "INVITE ");
        return;
    }

    bool nickExists = false;
    std::string invited = this->clients[client_fd].second.params[0];
    std::string channel = this->clients[client_fd].second.params[1];
    
    std::map<int, std::pair<int, Client> >::iterator it = this->clients.begin();
    while (it != this->clients.end())
    {
        if (areEqualScandi(it->second.second.nick, invited))
        {
            nickExists = true;
        }
        it++;
    }
    if (!nickExists)
    {
        serverResponse(client_fd, ERR_NOSUCHNICK, RED, invited + " ");
        return;
    }

    if (this->channels.count(channel) == 0)
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL, RED, channel + " ");
        return;
    }

    bool IsOperator = false;
    std::string operatorNick = this->clients[client_fd].second.nick;
    for (size_t i = 0; i < this->channels[channel].operators.size(); i++)
    {
        if (areEqualScandi(operatorNick, this->channels[channel].operators[i]))
        {
            IsOperator = true;
        }
    }
    if (!IsOperator)
    {
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED, RED, channel + " ");
        return;
    }

    Channel& chan = this->channels[channel];
    bool already = false;
    if (chan.isAnyMember(invited))
        already = true;
    for (size_t i = 0; i < chan.invited_users.size(); i++)
    {
        if (areEqualScandi(chan.invited_users[i], invited))
        {
            already = true;
        }
    }
    if (already)
    {
        serverResponse(client_fd, ERR_USERONCHANNEL, RED, invited + " " + channel + " ");
        return;
    }
    this->channels[channel].invited_users.push_back(invited);

    std::string inviteeMessage = ":" + operatorNick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " INVITE " + invited + ":" + chan.name + "\r\n";
    this->sendMessageByNick(invited, inviteeMessage);

    serverResponse(client_fd, RPL_INVITING, GREEN, chan.name + " " + invited);
}

void Server::topicCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, RED, "");
        return;
    }
    if (this->clients[client_fd].second.params.size() < 1)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "TOPIC ");
        return;
    }
    if (this->channels.count(this->clients[client_fd].second.params.front()) == 0 || !validChanName(this->clients[client_fd].second.params.front()))
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL, RED, this->clients[client_fd].second.params.front() + " ");
        return;
    }

    bool IsOperator = false;
    std::string chan_name = this->clients[client_fd].second.params.front();
    std::string nick = this->clients[client_fd].second.nick;
    for (size_t i = 0; i < this->channels[chan_name].operators.size(); i++)
    {
        if (areEqualScandi(nick, this->channels[chan_name].operators[i]))
        {
            IsOperator = true;
        }
    }
    if (!IsOperator)
    {
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED, RED, chan_name + " ");
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        std::string message = ":" + nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " TOPIC " + chan_name + ":" + this->clients[client_fd].second.params[1];
        this->channels[chan_name].broadcastToAll(this->clients, this->clients[client_fd].second, message, true);
        
        this->channels[chan_name].topic = this->clients[client_fd].second.params[1];
    }
    else
    {
        if (this->channels[chan_name].topic.empty())
        {
            serverResponse(client_fd, RPL_NOTOPIC, GREEN, chan_name);
        }
        else
        {
            serverResponse(client_fd, RPL_TOPIC, GREEN, chan_name + " :" + this->channels[chan_name].topic);
        }
    }
}

void Server::modeCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, RED, "");
        return;
    }

    if (this->clients[client_fd].second.params.size() < 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "MODE ");
        return;
    }

    std::string mode = this->clients[client_fd].second.params[1];
    std::string chan_name = this->clients[client_fd].second.params.front();
    if (this->channels.count(chan_name) == 0 || !validChanName(chan_name))
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL, RED, chan_name);
        return;
    }

    bool IsOperator = false;
    for (size_t i = 0; i < this->channels[chan_name].operators.size(); i++)
    {
        if (areEqualScandi(this->clients[client_fd].second.nick, this->channels[chan_name].operators[i]))
        {
            IsOperator = true;
        }
    }

    if (!IsOperator)
    {
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED, RED, this->clients[client_fd].second.nick + " ");
        return;
    }

    if (mode == "+i")
    {
        this->channels[chan_name].invite_only = true;
    }
    else if (mode == "-i")
    {
        this->channels[chan_name].invite_only = false;
    }
    else if (mode == "-t")
    {
        this->channels[chan_name].topic_restricted = true;
    }
    else if (mode == "-t")
    {
        this->channels[chan_name].topic_restricted = false;
    }
    else if (mode == "+k")
    {
        if (this->clients[client_fd].second.params.size() < 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "MODE ");
            return;
        }
        else if (!this->channels[chan_name].password.empty())
        {
            serverResponse(client_fd, ERR_KEYSET, RED, chan_name + " ");
        }
        this->channels[chan_name].password = this->clients[client_fd].second.params[2];
    }
    else if (mode == "-k")
    {
        this->channels[chan_name].password.clear();
    }
    else if (mode == "+o")
    {
        if (this->clients[client_fd].second.params.size() < 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "MODE ");
            return;
        }
        std::string chan_name = this->clients[client_fd].second.params[0];
        std::string nick = this->clients[client_fd].second.params[2];
        for (size_t i = 0; i < this->channels[chan_name].operators.size(); i++)
        {
            if (areEqualScandi(this->channels[chan_name].operators[i], nick))
            {
                return;
            }
        }
        bool nickInChan = false;
        for (size_t i = 0; i < this->channels[chan_name].members.size(); i++)
        {
            if (areEqualScandi(this->channels[chan_name].members[i], nick))
            {
                nickInChan = true;
            }
        }
        if (!nickInChan)
        {
            serverResponse(client_fd, ERR_USERNOTINCHANNEL, RED, nick + " " + chan_name + " ");
            return;
        }
        std::vector<std::string>& members = this->channels[chan_name].members;
        members.erase(std::remove(members.begin(), members.end(), nick), members.end());
        this->channels[chan_name].operators.push_back(nick);
    }
    else if (mode == "-o")
    {
        if (this->clients[client_fd].second.params.size() < 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "MODE ");
            return;
        }
        std::string chan_name = this->clients[client_fd].second.params[0];
        std::string nick = this->clients[client_fd].second.params[2];

        if (this->channels[chan_name].operators.size() == 1)
        {
            return;
        }
        bool isOper = false;
        for (size_t i = 0; i < this->channels[chan_name].operators.size(); i++)
        {
            if (areEqualScandi(this->channels[chan_name].operators[i], nick))
            {
                isOper = true;
                break;
            }
        }
        if (isOper)
        {
            std::vector<std::string>& ops = this->channels[chan_name].operators;
            ops.erase(std::remove(ops.begin(), ops.end(), nick), ops.end());
            this->channels[chan_name].members.push_back(nick);
        }
    }
    else if (mode == "+l")
    {
        if (this->clients[client_fd].second.params.size() < 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "MODE ");
            return;
        }
        size_t limit;
        std::stringstream ss(this->clients[client_fd].second.params[2]);

        ss >> limit;
        if (!ss.eof() || ss.fail())
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "MODE ");
            return;
        }

        std::string chan_name = this->clients[client_fd].second.params[0];
        if (this->channels.count(chan_name) == 0)
        {
            serverResponse(client_fd, ERR_NOSUCHCHANNEL, RED, chan_name + " ");
            return;
        }

        this->channels[chan_name].max_users = limit;
        this->channels[chan_name].userlimited = true;
    }
    else if (mode == "-l")
    {
        if (this->clients[client_fd].second.params.size() < 2)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS, RED, "MODE ");
            return;
        }
        this->channels[chan_name].userlimited = false;
    }
    else
    {
        serverResponse(client_fd, ERR_UNKNOWNMODE, RED, mode + " 472 :is unknown mode char to me for " + mode[1]);
        return ;
    }
    std::string message = ":" + this->clients[client_fd].second.nick + "!" + this->clients[client_fd].second.user + "@" + this->clients[client_fd].second.host + " MODE " + chan_name;
    for (size_t i = 1; i < this->clients[client_fd].second.params.size(); i++)
    {
        message += " " + this->clients[client_fd].second.params[i];
    }
    this->channels[chan_name].broadcastToAll(this->clients, this->clients[client_fd].second, message, true);
}
