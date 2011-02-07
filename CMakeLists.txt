cmake_minimum_required(VERSION 2.8)

PROJECT(relayd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3)

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

ADD_EXECUTABLE(relayd main.c dhcp.c route.c)
TARGET_LINK_LIBRARIES(relayd ubox)

SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS relayd
	RUNTIME DESTINATION sbin
)
