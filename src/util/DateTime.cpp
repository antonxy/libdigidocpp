/*
 * libdigidocpp
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "DateTime.h"

#include "log.h"

#include <cstring>

using namespace digidoc::util;
using namespace std;

struct tm date::gmtime(time_t t)
{
    tm tm {};
#ifdef _WIN32
    if(gmtime_s(&tm, &t) != 0)
#else
    if(!gmtime_r(&t, &tm))
#endif
        THROW("Failed to convert time_t to tm");
    return tm;
}

struct tm date::from_string(const string &time)
{
    tm tm {};
    if(time.empty())
        return tm;
    // Parse ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
    int year = 0, mon = 0, mday = 0, hour = 0, min = 0, sec = 0;
    if(sscanf(time.c_str(), "%d-%d-%dT%d:%d:%d",
        &year, &mon, &mday, &hour, &min, &sec) == 6)
    {
        tm.tm_year = year - 1900;
        tm.tm_mon = mon - 1;
        tm.tm_mday = mday;
        tm.tm_hour = hour;
        tm.tm_min = min;
        tm.tm_sec = sec;
    }
    // Returns zeroed tm if parsing fails (consistent with is_empty() check)
    return tm;
}

bool date::is_empty(const tm &t)
{
    return t.tm_sec == 0 &&
        t.tm_min == 0 &&
        t.tm_hour == 0 &&
        t.tm_mday == 0 &&
        t.tm_mon == 0 &&
        t.tm_year == 0 &&
        t.tm_wday == 0 &&
        t.tm_yday == 0 &&
        t.tm_isdst == 0;
}

time_t date::mkgmtime(tm &t)
{
#ifdef _WIN32
    return _mkgmtime(&t);
#else
    return timegm(&t);
#endif
}

string date::to_string(time_t t)
{
    return to_string(gmtime(t));
}

string date::to_string(const tm &date)
{
    string result(20, 0);
    if(is_empty(date) || strftime(result.data(), result.size() + 1, "%Y-%m-%dT%H:%M:%SZ", &date) == 0)
        result.clear();
    return result;
}
