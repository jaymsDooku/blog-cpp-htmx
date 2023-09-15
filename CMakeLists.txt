cmake_minimum_required(VERSION 3.26)
project(blog_cpp)

set(CMAKE_CXX_STANDARD 17)

find_package(Crow)
find_package(SQLiteCpp)
find_package(libsodium)
find_package(maddy)

add_executable(blog_cpp main.cpp)

target_link_libraries(blog_cpp Crow::Crow SQLiteCpp libsodium::libsodium maddy::maddy)
