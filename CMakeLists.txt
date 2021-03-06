PROJECT (mpc LANGUAGES CXX)
CMAKE_MINIMUM_REQUIRED(VERSION 3.11.0)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

SET(CMAKE_CXX_FLAGS "-Wall -Wextra")
SET(CMAKE_CXX_FLAGS_DEBUG "-g")
SET(CMAKE_CXX_FLAGS_RELEASE "-O3")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_DEBUG_MACRO")
SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

FIND_PACKAGE(SEAL 3.6 REQUIRED)

ADD_EXECUTABLE(
	muladd
	src/simple_muladd.cpp)

TARGET_LINK_LIBRARIES(muladd SEAL::seal)

ADD_EXECUTABLE(
	testing_parameters
	src/testing_parameters.cpp)

TARGET_LINK_LIBRARIES(testing_parameters SEAL::seal)

ADD_EXECUTABLE(
	mpcseal
	src/simple_mpc.cpp)

TARGET_LINK_LIBRARIES(mpcseal SEAL::seal)