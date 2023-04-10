# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
    ./src/common/MuxLogger.cpp \
    ./src/common/MuxPortConfig.cpp \
    ./src/common/State.cpp \
    ./src/common/StateMachine.cpp 

OBJS += \
    ./src/common/MuxLogger.o \
    ./src/common/MuxPortConfig.o \
    ./src/common/State.o \
    ./src/common/StateMachine.o 

CPP_DEPS += \
    ./src/common/MuxLogger.d \
    ./src/common/MuxPortConfig.d \
    ./src/common/State.d \
    ./src/common/StateMachine.d 


# Each subdirectory must supply rules for building sources it contributes
src/common/%.o: src/common/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -std=c++17 -D__FILENAME__="$(subst src/,,$<)" $(BOOST_MACROS) $(INCLUDES) $(CPPFLAGS) -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


