cmake_minimum_required(VERSION 3.8)
project(Injector VERSION 0.1.0)

add_executable("Injector" "main.cpp" "injection.h" "injection.cpp")

set_target_properties(Injector PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "../Release"
    CMAKE_CXX_STANDARD 20
    CPACK_PROJECT_NAME ${PROJECT_NAME}
    CPACK_PROJECT_VERSION ${PROJECT_VERSION}
    
)
