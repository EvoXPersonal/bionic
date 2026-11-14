/*
 * Copyright (C) 2026 AxionOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

bool custom_rom_hide_is_app_process();

bool custom_rom_hide_should_spoof_prop(const char* name, char* value);
bool custom_rom_hide_should_hide_prop(const char* name);
// buffer must hold PROP_VALUE_MAX bytes; a dynamic result remains valid while buffer lives.
const char* custom_rom_hide_get_prop_override(const char* name, char* buffer);

__END_DECLS