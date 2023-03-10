/*
 *  Copyright 2021 (c) Microsoft Corporation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * MuxLogger.cpp
 *
 *  Created on: Oct 4, 2020
 *      Author: Tamer Ahmed
 */

#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/file.hpp>
#include "boost/log/utility/setup/from_settings.hpp"
#include <boost/log/utility/exception_handler.hpp>
#include <boost/filesystem.hpp>

#include "MuxException.h"
#include "MuxLogger.h"

namespace common
{

const MuxLogger::BoostLogPriorityMap MuxLogger::boostLogPriorityMap = {
    { boost::log::sinks::syslog::emergency, boost::log::trivial::fatal },
    { boost::log::sinks::syslog::alert, boost::log::trivial::fatal },
    { boost::log::sinks::syslog::critical, boost::log::trivial::fatal },
    { boost::log::sinks::syslog::error, boost::log::trivial::error },
    { boost::log::sinks::syslog::warning, boost::log::trivial::error },
    { boost::log::sinks::syslog::notice, boost::log::trivial::warning },
    { boost::log::sinks::syslog::info, boost::log::trivial::info },
    { boost::log::sinks::syslog::debug, boost::log::trivial::trace }
};

const MuxLogger::SyslogPriorityMap MuxLogger::syslogPriorityMap = {
    { boost::log::trivial::fatal, boost::log::sinks::syslog::alert },
    { boost::log::trivial::error, boost::log::sinks::syslog::error },
    { boost::log::trivial::warning, boost::log::sinks::syslog::notice },
    { boost::log::trivial::info, boost::log::sinks::syslog::info },
    { boost::log::trivial::debug, boost::log::sinks::syslog::debug },
    { boost::log::trivial::trace, boost::log::sinks::syslog::debug }
};

//
// ---> operator()(const boost::log::runtime_error &ex);
//
// handles runtime error exceptions
//
void MuxLoggerExceptionHandler::operator()(const boost::log::runtime_error &ex) const
{
    std::ostringstream errMsg;
    errMsg << "MUX Logger exception!!" << ". Exception details: " << ex.what();

    throw MUX_ERROR(MuxLogger, errMsg.str());
}

//
// ---> operator()(const std::exception &ex);
//
// handles std exceptions
//
void MuxLoggerExceptionHandler::operator()(const std::exception &ex) const
{
    std::ostringstream errMsg;
    errMsg << "MUX Logger exception!!" << ". Exception details: " << ex.what();

    throw MUX_ERROR(MuxLogger, errMsg.str());
}

//
// ---> getInstance();
//
// constructs MuxLogger singleton instance
//
MuxLoggerPtr MuxLogger::getInstance()
{
    static std::shared_ptr<MuxLogger> MuxLoggerPtr = nullptr;

    if (MuxLoggerPtr == nullptr) {
        MuxLoggerPtr = std::shared_ptr<MuxLogger> (new MuxLogger);
    }

    return MuxLoggerPtr;
}

void MuxLogger::swssPrioNotify(const std::string& component, const std::string& prioStr)
{
    namespace sinks = boost::log::sinks;

    if (swss::Logger::priorityStringMap.find(prioStr) != swss::Logger::priorityStringMap.end()) {
        auto syslog_level = static_cast<sinks::syslog::level>(swss::Logger::priorityStringMap.at(prioStr));
        if (boostLogPriorityMap.find(syslog_level) != boostLogPriorityMap.end()) {
            auto boost_log_level = boostLogPriorityMap.at(syslog_level);
            MUXLOGFATAL(boost::format("Updated log level to: %s") % boost_log_level);
            getInstance()->setLevel(boost_log_level);
        }
    }
}

void MuxLogger::swssOutputNotify(const std::string& component, const std::string& outputStr)
{
    if (outputStr != "SYSLOG") {
        MUXLOGFATAL("Invalid logoutput, linkmgrd only supports 'SYSLOG'.");
    }
}

//
// ---> initialize(std::string &prog,
//                 std::string &path,
//                 boost::log::trivial::severity_level level);
//
// initialize MUX logging class
//
void MuxLogger::initialize(
    std::string &prog,
    std::string &path,
    boost::log::trivial::severity_level level,
    bool extraLogFile,
    bool linkToSwssLogger
)
{
    namespace trivial = boost::log::trivial;
    namespace keywords = boost::log::keywords;
    namespace sinks = boost::log::sinks;

    mLevel = level;

    boost::log::register_simple_formatter_factory<trivial::severity_level, char> ("Severity");

    boost::log::settings settings;
    boost::log::init_from_settings(settings);

    if (extraLogFile) {
        boost::filesystem::remove(path);
        boost::log::add_file_log(
            keywords::file_name = path,
            keywords::format = "[%TimeStamp%] [%Severity%] %Message%"
        );
    }

    boost::log::add_common_attributes();
    boost::log::core::get()->set_exception_handler(
        boost::log::make_exception_handler<boost::log::runtime_error, std::exception> (MuxLoggerExceptionHandler())
    );

    addSyslogSink(prog);

    if (linkToSwssLogger) {
        const std::string dbname = "linkmgrd";

        if (syslogPriorityMap.find(level) != syslogPriorityMap.end()) {
            auto syslogPrio = syslogPriorityMap.at(level);

            for (auto const &p : swss::Logger::priorityStringMap) {
                if (static_cast<sinks::syslog::level>(p.second) == syslogPrio) {
                    swss::Logger::linkToDbNative(dbname);
                    // replace priority and output observers with local ones
                    swss::Logger::linkToDbWithOutput(
                        dbname,
                        swssPrioNotify,
                        p.first,
                        swssOutputNotify,
                        "SYSLOG"
                    );
                    break;
                }
            }
        }
    }
}

//
// ---> setLevel(const boost::log::trivial::severity_level level);
//
// set logger frontend and backend filter level
//
void MuxLogger::setLevel(const boost::log::trivial::severity_level level)
{
    namespace trivial = boost::log::trivial;

    mLevel = level;
    boost::log::core::get()->set_filter(trivial::severity >= level);
}

//
// ---> addSyslogSink(std::string &prog);
//
// Add syslog sink
//
void MuxLogger::addSyslogSink(std::string &prog)
{
    namespace sinks = boost::log::sinks;
    try {
        // Create a syslog sink
        boost::shared_ptr<sinks::syslog_backend> sink(new sinks::syslog_backend(
            boost::log::keywords::facility = sinks::syslog::user,
            boost::log::keywords::use_impl = sinks::syslog::native
        ));

        // Create and fill in another level translator for "Severity" attribute of type string
        sinks::syslog::custom_severity_mapping<boost::log::trivial::severity_level> mapping("Severity");
        for (auto const &p : syslogPriorityMap) {
            mapping[p.first] = p.second;
        }
        sink->set_severity_mapper(mapping);

        // Add the sink to the core
        boost::log::core::get()->add_sink(boost::make_shared<sinks::synchronous_sink<sinks::syslog_backend>> (sink));
    }
    catch (std::exception& ex) {
        std::ostringstream errMsg;
        errMsg << "MUX Logger exception!!" << ". Exception details: " << ex.what();

        throw MUX_ERROR(MuxLogger, errMsg.str());
   }
}

} /* namespace common */
