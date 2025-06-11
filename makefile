CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -I.
LDFLAGS = -lpcap

TARGET = tls-block
SRCS = main.cpp mac.cpp ip.cpp packet_handler.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
