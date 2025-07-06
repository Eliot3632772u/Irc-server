#include "client.hpp"

bool Client::hasChannel(std::string& name)
{
    for (size_t i = 0; i < this->channels.size(); i++)
    {
        if (areEqualScandi(name, this->channels[i]))
            return true;
    }
    return false;
}


void Client::removeChannel(std::string chan)
{
	for (size_t i = 0; i < this->channels.size(); i++)
	{
		if (areEqualScandi(chan, this->channels[i]))
		{
			this->channels.erase(this->channels.begin() + i);
			break;
		}
	}
}