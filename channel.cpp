#include "channel.hpp"

bool Channel::isAnyMember(const std::string& nick) const
{
	for (size_t i = 0; i < this->members.size(); i++)
	{
		if (nick == this->members[i])
		{
			return true;
		}
	}

	for (size_t i = 0; i < this->operators.size(); i++)
	{
		if (nick == this->operators[i])
		{
			return true;
		}
	}

	return false;
}

void Channel::broadcastToAll(std::map<int, std::pair<int, Client> >& recipients, Client& sender, std::string message, bool include_sender) const
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
	if (include_sender)
	{
		send(sender.client_fd, message.c_str(), message.size(), MSG_NOSIGNAL);
	}
}

Channel::Channel(){

	this->invite_only = false;
	this->userlimited = false;
	this->topic_restricted = false;
}

void Channel::removeMember(std::string nick)
{
	this->members.erase(std::remove(this->members.begin(), this->members.end(), nick), this->members.end());
	this->operators.erase(std::remove(this->operators.begin(), this->operators.end(), nick), this->operators.end());
}