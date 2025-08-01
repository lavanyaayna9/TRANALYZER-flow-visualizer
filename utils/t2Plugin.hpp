/*
 * t2Plugin.hpp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef T2_T2PLUGIN_HPP_INCLUDED
#define T2_T2PLUGIN_HPP_INCLUDED

#define T2_API extern "C"

extern "C" {
    #include "t2Plugin.h"
}

#undef T2_PLUGIN_STRUCT_NEW
// 'plStruct' MUST be free'd in t2Finalize()
#define T2_PLUGIN_STRUCT_NEW(plStruct) \
    if (UNLIKELY(!(plStruct = static_cast<decltype(plStruct)>(t2_calloc(mainHashMap->hashChainTableSize, sizeof(*(plStruct))))))) { \
        T2_PFATAL(plugin_name, "failed to allocate memory for " STR(plStruct)); \
    }

#endif // T2_T2PLUGIN_HPP_INCLUDED
