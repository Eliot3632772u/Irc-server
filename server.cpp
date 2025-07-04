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

        int ready_fds = epoll_wait(this->epollFd, events, 100, -1);
        std::cout << "waiting :" << std::endl;
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
                    for (int i = 0; i < this->clients.size(); i++)
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
            }
        }
    }
}

void Server::readReq(int client_fd)
{

    char buffer[550] = {0};

    ssize_t read_bytes;
    if ((read_bytes = read(client_fd, buffer, 549)) == -1)
        return;

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
        // throw message too long
        serverResponse(client_fd, status::ERR_INPUTTOOLONG); // check
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
            // parse message
            size_t last = this->clients[client_fd].second.buffer.size() - 3;
            this->clients[client_fd].second.buffer = this->clients[client_fd].second.buffer.substr(0, last);

            for (int i = 0; i < this->clients[client_fd].second.buffer.size(); i++)
            {

                if (this->clients[client_fd].second.buffer[i] == '\r' || this->clients[client_fd].second.buffer[i] == '\n')
                {

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

    std::string buffer = this->clients[client_fd].second.buffer;

    if (buffer[0] == ':')
    {

        std::string prefix;

        size_t prefixl;
        for (prefixl = 0; prefixl < buffer.size(); prefixl++)
        {

            if (buffer[prefixl] == ' ')
                break;
        }

        prefix = buffer.substr(0, prefixl - 1);

        int pos;
        for (int i = 0; i < prefix.size(); i++)
        {

            if (prefix[i] == '!' || prefix[i] == '@')
            {

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
    for (commandl = 0; commandl < buffer.size(); commandl++)
    {

        if (buffer[commandl] == ' ')
            break;
    }

    if (commandl > 0)
        command = buffer.substr(0, commandl - 1);
    else
    {

        clearClientData(client_fd);
        serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
        return;
    }

    for (int i = 0; i < command.size(); i++)
    {

        if (!isalpha(command[i]))
        {

            // throw not valid command
            clearClientData(client_fd);
            serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
            return;
        }
    }

    this->clients[client_fd].second.command = command;

    if (commandl + 1 < buffer.size())
        buffer = buffer.substr(commandl + 1);
    else
    {

        this->clients[client_fd].second.buffer.clear();
        // responde to message
        return;
    }

    while (buffer.size())
    {

        std::string param;

        size_t pos = buffer.find_first_not_of(' ');

        if (pos == std::string::npos)
        {

            this->clients[client_fd].second.buffer.clear();
            // respond to message
            // handle message
            return;
        }

        param = buffer.substr(0, pos - 1);

        if (pos + 1 < buffer.size())
            buffer = buffer.substr(pos + 1);
        else
            buffer = "";

        if (param[0] == ':')
        {

            this->clients[client_fd].second.params.push_back(param.substr(1));
            this->clients[client_fd].second.buffer.clear();
            // responde to message
            return;
        }

        this->clients[client_fd].second.params.push_back(param);
    }

    if (this->clients[client_fd].second.params.size() > 15)
    {

        serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
        return;
    }
}

void Server::serverResponse(int client_fd, enum status code)
{

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
    if (this->clients[client_fd].second.prefix.size() != 0 && this->clients[client_fd].second.prefix != this->clients[client_fd].second.nick)
    {
        serverResponse(client_fd, status::ERR_NOSUCHNICK);
        clearClientData(client_fd);
        return;
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
    else
    {
        serverResponse(client_fd, status::ERR_UNKNOWNCOMMAND);
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
        return;
    }

    if (this->clients[client_fd].second.params.size() > 1)
    {
        serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
        clearClientData(client_fd);
        return;
    }

    if (this->clients[client_fd].second.params.empty() || this->clients[client_fd].second.params.front() != this->serverPass)
    {
        serverResponse(client_fd, status::ERR_PASSWDMISMATCH);
        clearClientData(client_fd);
        return;
    }

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

    char &c = this->clients[client_fd].second.params.front()[0];
    if (!std::isalpha(c) && std::string("[]\\`_^{|}").find(c) == std::string::npos)
    {
        serverResponse(client_fd, status::ERR_ERRONEUSNICKNAME);
        clearClientData(client_fd);
        return;
    }

    for (size_t i = 1; i < this->clients[client_fd].second.params.front().size(); i++)
    {
        char &c = this->clients[client_fd].second.params.front()[i];
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
        serverResponse(client_fd, status::ERR_NOTREGISTERED);
        return;
    }

    // if (this->clients[client_fd].second.params.size() != 1) // shouldn't be since we have keys as well
    // {
    //     serverResponse(client_fd, status::ERR_NEEDMOREPARAMS);
    //     return;
    // }

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


    std::stringstream ssArgs(this->clients[client_fd].second.params.front()); // did not take into account keys 
    std::string channels;
    std::string keys;
    
    std::getline(ssArgs, channels, ' ');
    if (this->clients[client_fd].second.params.size() > 1)
        std::getline(ssArgs, keys);

    std::stringstream ssChans;
    std::string chan_name;

    while (std::getline(ssChans, chan_name, ','));
    {
        if (validChanName(chan_name))
        {
            if (this->channels.count(chan_name) > 0) // channel exits need to check further checks 
            {
                if (std::find(this->clients[client_fd].second.channels.begin(), this->clients[client_fd].second.channels.end(), chan_name) == this->clients[client_fd].second.channels.end())
                {
                    if (this->channels[chan_name].userlimited && this->channels[chan_name].members.size() + this->channels[chan_name].operators.size() == this->channels[chan_name].max_users)
                    {
                        serverResponse(client_fd, status::ERR_CHANNELISFULL);
                    }
                    else if (this->channels[chan_name].invite_only)
                    {
                        bool was_able_to_join = false;
                        for (size_t i = 0; i < this->channels[chan_name].invited_users.size(); i++)
                        {
                            if (areEqualScandi(this->channels[chan_name].invited_users[i], this->clients[client_fd].second.nick))
                            {
                                // send some message to other clients in channel and client that joined
                                this->channels[chan_name].invited_users.erase(this->channels[chan_name].invited_users.begin() + i);
                                this->channels[chan_name].members.push_back(this->clients[client_fd].second.nick);
                                this->clients[client_fd].second.channels.push_back(chan_name);
                                was_able_to_join = true;
                                break;
                            }
                        }
                        if (!was_able_to_join)
                        {
                            serverResponse(client_fd, status::ERR_INVITEONLYCHAN);
                        }
                    }
                    else
                    {
                        this->channels[chan_name].members.push_back(this->clients[client_fd].second.nick);
                        this->clients[client_fd].second.channels.push_back(chan_name);
                    }
                }
            }
            else // channel does not exist nned to create it and set client as operator for it.
            {
                Channel new_chan;
                new_chan.name = chan_name;

                this->clients[client_fd].second.channels.push_back(chan_name);

                new_chan.operators.push_back(this->clients[client_fd].second.nick);
                this->channels[chan_name] = new_chan;
                // inform other users but what other users there is none !
            }
        }
        else
        {
            serverResponse(client_fd, status::ERR_NOSUCHCHANNEL);
        }
    }

    serverResponse(client_fd, status::ERR_NOSUCHCHANNEL);
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
