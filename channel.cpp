#include "channel.hpp"
#include "client.hpp"

bool areEqualScandi(const std::string& one, const std::string& two);

bool Channel::isAnyMember(const std::string& nick) const
{
	for (size_t i = 0; i < this->members.size(); i++)
	{
		if (areEqualScandi(nick, this->members[i]))
		{
			return true;
		}
	}

	for (size_t i = 0; i < this->operators.size(); i++)
	{
		if (areEqualScandi(nick, this->operators[i]))
		{
			return true;
		}
	}

	return false;
}

void Channel::broadcastToAll(std::map<int, std::pair<int, Client> >& clients, int except, std::string message) const
{
	std::map<int, std::pair<int, Client> >::iterator it = clients.begin();
	while (it != clients.end())
	{
		std::cout << "SEND LOOP" << std::endl;
		if (except != it->second.second.client_fd && isAnyMember(it->second.second.nick))
		{
			std::cout << "Tried to send to " << it->second.second.nick << std::endl;
			message += "\r\n";
			send(it->second.second.client_fd, message.c_str(), message.size(), MSG_NOSIGNAL); // check failure
		}
	}
}

Channel::Channel(){

	this->invite_only = false;
	this->userlimited = false;
	this->topic_restricted = false;
}