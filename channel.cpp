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
		if (except != it->second.second.client_fd && isAnyMember(it->second.second.nick))
		{
			char* buffer = new char[message.size() + 1];
			std::strcpy(buffer, message.c_str());
			send(it->second.second.client_fd, buffer, message.size(), MSG_NOSIGNAL); // check failure
		}
	}
}