CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11
LDFLAGS = -lpcap
TARGET = tls-block

# ip.cpp와 mac.cpp를 컴파일 대상에 추가
SRCS = tls-block.cpp ip.cpp mac.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
