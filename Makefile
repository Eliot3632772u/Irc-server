NAME = ircserv
CPPC = c++
FLGS = #-std=c++98 # -Wall -Wextra -Werror -g -fsanitize=address
INCS = inc.hpp server.hpp
SRCS = main.cpp server.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(NAME)

%.o: %.cpp $(INCS)
	$(CPPC) $(FLGS) -c $< -o $@

$(NAME): $(OBJS)
	$(CPPC) $(FLGS) $(OBJS) -o $(NAME)

clean:
	rm -rf $(OBJS)

fclean: clean
	rm -rf $(NAME)

re: fclean all
