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

    this->epollFd = epoll_create1(0);
    if (this->epollFd < 0)
        initSocketsError("epoll_create: ", this->socketFd, NULL);

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.fd = this->socketFd;

    if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, this->socketFd, &event) == -1)
    {

        close(this->epollFd);
        initSocketsError("epoll_ctl", this->socketFd, NULL);
    }
}

void Server::acceptConnections()
{

    struct epoll_event events[100];

    while (true)
    {

        std::cout << "waiting :" << std::endl;
        int ready_fds = epoll_wait(this->epollFd, events, 100, -1);
        if (ready_fds < 0)
        {

            close(this->epollFd);
            initSocketsError("epoll_event: ", this->socketFd, NULL);
        }

        for (int i = 0; i < ready_fds; i++)
        {
            int fd = events[i].data.fd;
            
            if (fd == this->socketFd)
            {
                
                std::cout << ready_fds << std::endl;
                std::cout << fd << std::endl;
                int client_fd = accept(fd, NULL, NULL);
                if (client_fd < 0)
                {

                    close(this->epollFd);
                    initSocketsError("accept: ", this->socketFd, NULL);
                }

                fcntl(client_fd, F_SETFL, O_NONBLOCK);

                struct epoll_event event;
                event.events = EPOLLIN | EPOLLOUT | EPOLLET;
                event.data.fd = client_fd;

                if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, client_fd, &event) == -1)
                {

                    close(this->epollFd);
                    close(client_fd);
                    for (size_t i = 0; i < this->clients.size(); i++)
                        close(this->clients[i].first);

                    initSocketsError("epoll_ctl", this->socketFd, NULL);
                }

                this->clients[client_fd].second.client_fd = client_fd;

                continue;
            }
            else
            {
                // parse cmd
                readReq(fd);
                // if (!this->clients[fd].second.command.empty())
                //     handleMessage(fd);
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
        close(client_fd);
        this->clients.erase(client_fd);
        return;
    }

    std::string bufferString = buffer;


    if (bufferString.size() + this->clients[client_fd].second.buffer.size() > 512)
    {

        this->clients[client_fd].second.buffer.erase();
        serverResponse(client_fd, ERR_INPUTTOOLONG);
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

                if (this->clients[client_fd].second.buffer[i] == '\r' || this->clients[client_fd].second.buffer[i] == '\0' || this->clients[client_fd].second.buffer[i] == '\n')
                {
                    std::cout << "stop" << std::endl;
                    this->clients[client_fd].second.buffer.clear();
                    return;
                }
            }

            parseCmd(client_fd);

        }
    }

}

void Server::parseCmd(int client_fd)
{
    std::string buffer =  this->clients[client_fd].second.buffer;

    std::cout << "BUFFER: " << buffer << std::endl;
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
        serverResponse(client_fd, ERR_UNKNOWNCOMMAND);
        return;
    }
    
    for (size_t i = 0; i < command.size(); i++)
    {
        
        if (!isalpha(command[i]))
        {
            clearClientData(client_fd);
            serverResponse(client_fd, ERR_UNKNOWNCOMMAND);
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

        serverResponse(client_fd, ERR_NEEDMOREPARAMS);
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

void Server::handleMessage(int client_fd)
{
    std::string & command = this->clients[client_fd].second.command;
    if (this->clients[client_fd].second.prefix.size() != 0 && this->clients[client_fd].second.prefix != this->clients[client_fd].second.nick)
    {
        serverResponse(client_fd, ERR_NOSUCHNICK, this->clients[client_fd].second.nick);
        clearClientData(client_fd);
        return;
    }
    std::cout << "CMD: " << this->clients[client_fd].second.command << std::endl;
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
		serverResponse(client_fd, ERR_UNKNOWNCOMMAND, command + " ");
		clearClientData(client_fd);
		return ;
    }
}

void Server::botCMD(int client_fd){

    if (this->clients[client_fd].second.is_pass_set)
    {
        serverResponse(client_fd, ERR_ALREADYREGISTRED, "");
        clearClientData(client_fd);
        return ;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, this->clients[client_fd].second.command + " ");
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
        std::string res = ":irc.server.ma " + this->clients[client_fd].second.nick + " :Current time is ==> ";
        res += std::asctime(std::localtime(&result));
        if (!res.empty() && res[res.size() - 1] == '\n')
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
        serverResponse(client_fd, ERR_ALREADYREGISTRED, "");
        clearClientData(client_fd);
        std::cout << "PASS aleardy set" << std::endl << std::endl;
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, this->clients[client_fd].second.command + " ");
        clearClientData(client_fd);
        std::cout << "PASS alot of params" << std::endl << std::endl;
        return;
    }

    if (this->clients[client_fd].second.params.empty() || this->clients[client_fd].second.params.front() != this->serverPass)
    {
        serverResponse(client_fd, ERR_PASSWDMISMATCH, "");
        clearClientData(client_fd);
        std::cout << "INValid PASS " << std::endl << std::endl;
        return;
    }
    // to remove
    std::cout << "pass valid" << std::endl;

    this->clients[client_fd].second.is_pass_set = true;
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

void Server::nickCMD(int client_fd)
{
    if (this->clients[client_fd].second.is_pass_set == false)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, "");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, ERR_ERRONEUSNICKNAME, this->clients[client_fd].second.nick + " ");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.empty())
    {
        serverResponse(client_fd, ERR_NONICKNAMEGIVEN, "");
        clearClientData(client_fd);
        return;
    }

    for (size_t i = 0; i < this->clients.size(); i++)
    {
        if (this->clients[i].second.nick == this->clients[client_fd].second.params.front())
        {
            serverResponse(client_fd, ERR_NICKNAMEINUSE, this->clients[client_fd].second.nick + " ");
            clearClientData(client_fd);
            return;
        }
    }

    if (this->clients[client_fd].second.params.front().size() > 9)
    {
        serverResponse(client_fd, ERR_ERRONEUSNICKNAME, this->clients[client_fd].second.nick + " ");
        clearClientData(client_fd);
        return;
    }

    char &c = this->clients[client_fd].second.params.front()[0];
    if (!std::isalpha(c) && std::string("[]\\`_^{|}").find(c) == std::string::npos)
    {
        serverResponse(client_fd, ERR_ERRONEUSNICKNAME, this->clients[client_fd].second.nick + " ");
        clearClientData(client_fd);
        return;
    }

    for (size_t i = 1; i < this->clients[client_fd].second.params.front().size(); i++)
    {
        char &c = this->clients[client_fd].second.params.front()[i];
        if (!std::isalnum(c) && std::string("[]\\`_^{|}").find(c) == std::string::npos)
        {
            serverResponse(client_fd, ERR_ERRONEUSNICKNAME, this->clients[client_fd].second.nick + " ");
            clearClientData(client_fd);
            return;
        }
    }
    this->clients[client_fd].second.nick = this->clients[client_fd].second.params.front();

    if (!this->clients[client_fd].second.user.empty())
        this->clients[client_fd].second.authenticated = true;
    std::cout << "nickname done" << std::endl;
}

void Server::userCMD(int client_fd)
{
    if (this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_ALREADYREGISTRED, "");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.size() != 4)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, "USER ");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.front().size() > 9)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, "USER ");
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.front().find('@') != std::string::npos)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, "USER ");
        clearClientData(client_fd);
        return;
    }

    this->clients[client_fd].second.user = this->clients[client_fd].second.params.front();

    if (!this->clients[client_fd].second.nick.empty())
        this->clients[client_fd].second.authenticated = true;
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

void Server::joinCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, "");
        return;
    }

    if (this->clients[client_fd].second.params.empty() || this->clients[client_fd].second.params.size() > 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, "JOIN ");
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
                    // send message to clients of the channel
                    channel.members.erase(channel.members.begin() + j);
                    break;
                }
            }

            for (size_t j = 0; j < channel.operators.size(); j++)
            {
                if (areEqualScandi(this->clients[client_fd].second.nick, channel.operators[j]))
                {
                    // send message to clients of the channel
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
        if (validChanName(name))
        {
            if (this->channels.count(name) > 0) // channel exits need to check further checks 
            {
                if (std::find(this->clients[client_fd].second.channels.begin(), this->clients[client_fd].second.channels.end(), name) == this->clients[client_fd].second.channels.end())
                {
                    if (!this->channels[name].password.empty() && this->channels[name].password != keys_vec[i])
                    {
                        serverResponse(client_fd, ERR_BADCHANNELKEY, name + " ");
                        continue;
                    }
                    else if (this->channels[name].userlimited && this->channels[name].members.size() + this->channels[name].operators.size() == this->channels[name].max_users)
                    {
                        serverResponse(client_fd, ERR_CHANNELISFULL, name + " ");
                    }
                    else if (this->channels[name].invite_only)
                    {
                        bool was_able_to_join = false;
                        for (size_t i = 0; i < this->channels[name].invited_users.size(); i++)
                        {
                            if (areEqualScandi(this->channels[name].invited_users[i], this->clients[client_fd].second.nick))
                            {
                                // send some message to other clients in channel and client that joined
                                this->channels[name].invited_users.erase(this->channels[name].invited_users.begin() + i);
                                this->channels[name].members.push_back(this->clients[client_fd].second.nick);
                                this->clients[client_fd].second.channels.push_back(name);
                                was_able_to_join = true;
                                break;
                            }
                        }
                        if (!was_able_to_join)
                        {
                            serverResponse(client_fd, ERR_INVITEONLYCHAN, name + " ");
                        }
                    }
                    else
                    {
                        this->channels[name].members.push_back(this->clients[client_fd].second.nick);
                        this->clients[client_fd].second.channels.push_back(name);
                        // send join message
                    }
                }
            }
            else // channel does not exist nned to create it and set client as operator for it.
            {
                Channel new_chan;
                new_chan.name = name;

                this->clients[client_fd].second.channels.push_back(name);

                new_chan.operators.push_back(this->clients[client_fd].second.nick);
                this->channels[name] = new_chan;
                // inform other users but what other users there is none !
            }
        }
        else
        {
            serverResponse(client_fd, ERR_NOSUCHCHANNEL, name + " ");
        }
    }
}

void Server::privmsgCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, "");
        return;
    }
    if (this->clients[client_fd].second.params.empty())
    {
        serverResponse(client_fd, ERR_NORECIPIENT, ":No recipient given PRIVMSG");
        return;
    }
    if (this->clients[client_fd].second.params.size() == 1)
    {
        serverResponse(client_fd, ERR_NOTEXTTOSEND, "");
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
        else
        {
            users.push_back(target);
        }
    }
    
    std::string message = this->clients[client_fd].second.params[1];
    for (size_t i = 0; i < users.size(); i++)
    {
        std::string& target = users[i];
        bool sent = false;
        std::map<int, std::pair<int, Client> >::iterator it = this->clients.begin();
        while (it != this->clients.end())
        {
            std::string& connected = it->second.second.nick;
            if (areEqualScandi(target, connected))
            {
                char* buffer = new char[message.size() + 1];
                std::strcpy(buffer, message.c_str());
                send(it->second.second.client_fd, buffer, message.size(), MSG_NOSIGNAL); // check errors maybe? 
                sent = true; 
            }
            it++;
        }
        if (!sent)
        {
            serverResponse(client_fd, ERR_NOSUCHNICK, this->clients[client_fd].second.nick + " ");
        }
    }

    for (size_t i = 0; i < channels.size(); i++)
    {
        std::string& target = channels[i];
        if (this->channels.count(channels[i]) > 0)
        {
            this->channels[target].broadcastToAll(this->clients, client_fd, message);
        }
        else
        {
            serverResponse(client_fd, ERR_NOSUCHCHANNEL, target + " ");
        }
    }
}

void Server::kickCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, ":You have not registered");
        return;
    }
    if (this->clients[client_fd].second.params.size() < 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, "KICK ");
        return;
    }

    std::string channel = this->clients[client_fd].second.params[0];
    std::string targetNick = this->clients[client_fd].second.params[1];
    
    if (this->channels.count(channel) == 0)
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL, channel + " ");
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
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED, channel + " ");
        return;
    }

    Channel& chan = this->channels[channel];
    bool isMember = false;
    for (size_t i = 0; i < chan.members.size(); i++)
    {
        if (areEqualScandi(chan.members[i], targetNick))
        {
            isMember = true;
        }
    }
    if (!isMember)
    {
        serverResponse(client_fd, ERR_NOTONCHANNEL, channel + " ");
        return;
    }
    
    std::vector<std::string> memebers = this->channels[channel].members;
    memebers.erase(std::remove(memebers.begin(), memebers.end(), targetNick), memebers.end());
    std::map<int, std::pair<int, Client> >::iterator it = this->clients.begin();
    while (it != this->clients.end())
    {
        if (it->second.second.nick == targetNick)
        {
            break;
        }
        it++;
    }
    std::vector<std::string> chans = it->second.second.channels;
    std::vector<std::string>::iterator chan_it = chans.begin();
    while (chan_it != chans.end())
    {
        if (areEqualScandi(*chan_it, channel))
        {
            // send message
            chans.erase(chan_it);
            break;
        }
        chan_it++;
    }
}

void Server::inviteCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, "");
        return;
    }
    if (this->clients[client_fd].second.params.size() < 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, "INVITE ");
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
    }
    if (!nickExists)
    {
        serverResponse(client_fd, ERR_NOSUCHNICK, invited + " ");
        return;
    }

    if (this->channels.count(channel) == 0)
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL, channel + " ");
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
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED, channel + " ");
        return;
    }

    Channel& chan = this->channels[channel];
    bool already = false;
    for (size_t i = 0; i < chan.members.size(); i++)
    {
        if (areEqualScandi(chan.members[i], invited))
        {
            already = true;
        }
    }
    for (size_t i = 0; i < chan.operators.size(); i++)
    {
        if (areEqualScandi(chan.operators[i], invited))
        {
            already = true;
        }
    }
    for (size_t i = 0; i < chan.invited_users.size(); i++)
    {
        if (areEqualScandi(chan.invited_users[i], invited))
        {
            already = true;
        }
    }
    if (already)
    {
        serverResponse(client_fd, ERR_USERONCHANNEL, invited + " " + channel + " ");
        return;
    }
    if (this->channels[channel].invite_only)
    {
        this->channels[channel].invited_users.push_back(invited);
    }

}

void Server::topicCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED, "");
        return;
    }
    if (this->clients[client_fd].second.params.size() < 1)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS, "TOPIC ");
        return;
    }
    if (this->channels.count(this->clients[client_fd].second.params.front()) == 0 || !validChanName(this->clients[client_fd].second.params.front()))
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL, this->clients[client_fd].second.params.front() + " ");
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
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED, chan_name + " ");
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        this->channels[chan_name].topic = this->clients[client_fd].second.params[1];
        // send status change to clients of channel
    }
    else
    {
        // send topic to operator 
        // should send to other users as well.
    }
}

void Server::serverResponse(int client_fd, enum status code, std::string msg)
{
    if (ERR_ERRONEUSNICKNAME == code)
        msg += ":Erroneous nickname\r\n";
    else if (ERR_UNKNOWNCOMMAND == code)
        msg += ":Unknown command\r\n";
    else if (ERR_NOSUCHNICK == code)
        msg += ":No such nick/channel\r\n";
    else if (ERR_ALREADYREGISTRED == code)
        msg += ":Unauthorized command (already registered)\r\n";
    else if (ERR_NEEDMOREPARAMS == code)
        msg += ":Not enough parameters\r\n";
    else if (ERR_PASSWDMISMATCH == code)
        msg += ":Password incorrect\r\n";
    else if (ERR_NOTREGISTERED == code)
        msg += ":You have not registered\r\n";
    else if (ERR_ERRONEUSNICKNAME == code)
        msg += ":Erroneous nickname\r\n";
    else if (ERR_NONICKNAMEGIVEN == code)
        msg += ":No nickname given\r\n";
    else if (ERR_NICKNAMEINUSE == code)
        msg += ":Nickname is already in use\r\n";
    else if (ERR_BADCHANNELKEY == code)
        msg += ":Cannot join channel (+k)\r\n";
    else if (ERR_INVITEONLYCHAN == code)
        msg += ":Cannot join channel (+i)\r\n";
    else if (ERR_CHANNELISFULL == code)
        msg += ":Cannot join channel (+l)\r\n";
    else if (ERR_NOSUCHCHANNEL == code)
        msg += ":No such channel\r\n";
    else if (ERR_NORECIPIENT == code)
        msg += "\r\n";
    else if (ERR_NOTEXTTOSEND == code)
        msg += ":No text to send\r\n";
    else if (ERR_CHANOPRIVSNEEDED == code)
        msg += ":You're not channel operator\r\n";
    else if (ERR_NOTONCHANNEL == code)
        msg += ":You're not on that channel\r\n"
    else if (ERR_USERONCHANNEL == code)
        msg += ":is already on channel\r\n";
    else if (
    
    send(client_fd, msg.c_str(), msg.size(), MSG_NOSIGNAL);
}

void Server::modeCMD(int client_fd)
{
    if (!this->clients[client_fd].second.authenticated)
    {
        serverResponse(client_fd, ERR_NOTREGISTERED);
        return;
    }

    if (this->clients[client_fd].second.params.empty() || this->clients[client_fd].second.params.size() < 2)
    {
        serverResponse(client_fd, ERR_NEEDMOREPARAMS);
        return;
    }

    if (this->channels.count(this->clients[client_fd].second.params.front()) == 0 || !validChanName(this->clients[client_fd].second.params.front()))
    {
        serverResponse(client_fd, ERR_NOSUCHCHANNEL);
        return;
    }

    bool IsOperator = false;
    for (size_t i = 0; i < this->channels[this->clients[client_fd].second.params.front()].operators.size(); i++)
    {
        if (areEqualScandi(this->clients[client_fd].second.nick, this->channels[this->clients[client_fd].second.params.front()].operators[i]))
        {
            IsOperator = true;
        }
    }

    if (!IsOperator)
    {
        serverResponse(client_fd, ERR_CHANOPRIVSNEEDED);
        return;
    }

    if (this->clients[client_fd].second.params[1] == "+i")
    {
        this->channels[this->clients[client_fd].second.params.front()].invite_only = true;
    }
    else if (this->clients[client_fd].second.params[1] == "-i")
    {
        this->channels[this->clients[client_fd].second.params.front()].invite_only = false;
    }
    else if (this->clients[client_fd].second.params[1] == "-t")
    {
        this->channels[this->clients[client_fd].second.params.front()].topic_restricted = true;
    }
    else if (this->clients[client_fd].second.params[1] == "-t")
    {
        this->channels[this->clients[client_fd].second.params.front()].topic_restricted = false;
    }
    else if (this->clients[client_fd].second.params[1] == "+k")
    {
        if (this->clients[client_fd].second.params.size() != 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS);
            return;
        }
        this->channels[this->clients[client_fd].second.params.front()].password = this->clients[client_fd].second.params.back();
    }
    else if (this->clients[client_fd].second.params[1] == "-k")
    {
        if (this->clients[client_fd].second.params.size() != 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS);
            return;
        }
        if (this->channels[this->clients[client_fd].second.params.front()].password == this->clients[client_fd].second.params.back())
        {
            this->channels[this->clients[client_fd].second.params.front()].password.clear();
        }
    }
    else if (this->clients[client_fd].second.params[1] == "+o")
    {
        if (this->clients[client_fd].second.params.size() < 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS);
            return;
        }
        std::string chan_name = this->clients[client_fd].second.params[0];
        std::string nick = this->clients[client_fd].second.params[2];
        bool nickInChan = false;
        for (size_t i = 0; i < this->channels[chan_name].members.size(); i++)
        {
            if (areEqualScandi(this->channels[chan_name].members[i], nick))
            {
                nickInChan = true;
            }
        }
        bool isOper = false;
        for (size_t i = 0; i < this->channels[chan_name].operators.size(); i++)
        {
            if (areEqualScandi(this->channels[chan_name].operators[i], nick))
            {
                isOper = true;
            }
        }
        if (!nickInChan && !isOper)
        {
            serverResponse(client_fd, ERR_USERNOTINCHANNEL);
            return;
        }
        else if (!isOper)
        {
            std::vector<std::string>& members = this->channels[chan_name].members;
            members.erase(std::remove(members.begin(), members.end(), nick), members.end());
            this->channels[chan_name].operators.push_back(nick);
        }
    }
    else if (this->clients[client_fd].second.params[1] == "-o")
    {
        if (this->clients[client_fd].second.params.size() < 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS);
            return;
        }
        std::string chan_name = this->clients[client_fd].second.params[0];
        std::string nick = this->clients[client_fd].second.params[2];

        if (this->channels[chan_name].operators.size() == 1)
        {
            // user is the only chanop
            return;
        }
        bool isOper = false;
        for (size_t i = 0; i < this->channels[chan_name].operators.size(); i++)
        {
            if (areEqualScandi(this->channels[chan_name].operators[i], nick))
            {
                isOper = true;
            }
        }
        if (isOper)
        {
            std::vector<std::string>& ops = this->channels[chan_name].operators;
            ops.erase(std::remove(ops.begin(), ops.end(), nick), ops.end());
            this->channels[chan_name].members.push_back(nick);
        }
    }
    else if (this->clients[client_fd].second.params[1] == "+l")
    {
        if (this->clients[client_fd].second.params.size() < 3)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS);
            return;
        }
        size_t limit;
        std::stringstream ss(this->clients[client_fd].second.params[2]);

        ss >> limit;
        if (!ss.eof() || ss.fail())
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS);
            return;
        }

        std::string chan_name = this->clients[client_fd].second.params[0];
        if (this->channels.count(chan_name) == 0)
        {
            serverResponse(client_fd, ERR_NOSUCHCHANNEL);
            return;
        }

        this->channels[chan_name].max_users = limit;
        this->channels[chan_name].userlimited = true;
    }
    else if (this->clients[client_fd].second.params[1] == "-l")
    {
        if (this->clients[client_fd].second.params.size() < 2)
        {
            serverResponse(client_fd, ERR_NEEDMOREPARAMS);
            return;
        }

        std::string chan_name = this->clients[client_fd].second.params[0];
        if (this->channels.count(chan_name) == 0)
        {
            serverResponse(client_fd, ERR_NOSUCHCHANNEL);
            return;
        }
        this->channels[chan_name].userlimited = false;
    }
    else
    {
        serverResponse(client_fd, ERR_UNKNOWNMODE);
    }
}
