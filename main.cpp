#include "inc.hpp"
#include "server.hpp"

int main(int ac, char **av)
{
	if (ac != 3)
		return 1;

	signal(SIGPIPE, SIG_IGN);

  	Server server(av[2], av[1]);

	server.initSocket();
	server.creatEpoll();
	server.acceptConnections();
}