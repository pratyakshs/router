PROJECT_ROOT := .

CPP_FILES := $(wildcard *.cpp)
OBJ_FILES := $(CPP_FILES:%.cpp=build/%.o)


build/%.o: $(PROJECT_ROOT)/%.cpp
	g++ -c -std=c++11 -I$(PROJECT_ROOT)/include $< -o $@

# all: $(OBJ_FILES)
	# echo $(OBJ_FILES)

all: router.cpp
	g++ -g -pthread -std=c++11 -Iinclude -o router router.cpp
