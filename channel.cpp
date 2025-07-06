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

void Channel::broadcastToAll(std::map<int, std::pair<int, Client> >& recipients, Client& sender, std::string message) const
{
	message += "\r\n";

	std::map<int, std::pair<int, Client> >::iterator it = recipients.begin();
	
	while (it != recipients.end())
	{
		if (sender.nick != it->second.second.nick && isAnyMember(it->second.second.nick))
		{
			send(it->second.second.client_fd, message.c_str(), message.size(), MSG_NOSIGNAL);
		}
		it++;
	}
}

Channel::Channel(){

	this->invite_only = false;
	this->userlimited = false;
	this->topic_restricted = false;
}