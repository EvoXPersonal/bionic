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

#include "custom_rom_hide.h"

#include <fcntl.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <unistd.h>
#include <private/android_filesystem_config.h>

// This file is linked into the loader as well, which has neither ELF TLS nor a
// working __system_property_get at every call site, so keep it to plain string
// operations and raw syscalls.

static inline int raw_openat(const char* path, int flags) {
  return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags, 0));
}

static inline ssize_t raw_read(int fd, void* buf, size_t count) {
  return syscall(__NR_read, fd, buf, count);
}

static inline int raw_close(int fd) {
  return static_cast<int>(syscall(__NR_close, fd));
}

static bool read_cmdline_name(char* out, size_t out_size) {
  if (out_size == 0) return false;
  int fd = raw_openat("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;

  ssize_t n = raw_read(fd, out, out_size - 1);
  raw_close(fd);
  if (n <= 0) return false;

  out[n] = '\0';
  if (char* colon = strchr(out, ':')) *colon = '\0';
  return true;
}

static bool name_is_zygote(const char* name) {
  if (strcmp(name, "app_process") == 0 || strcmp(name, "app_process64") == 0 ||
      strcmp(name, "app_process32") == 0) {
    return true;
  }
  size_t len = strlen(name);
  static const char kZygoteSuffix[] = "_zygote";
  size_t slen = sizeof(kZygoteSuffix) - 1;
  if (len >= slen && strcmp(name + len - slen, kZygoteSuffix) == 0) return true;
  if (strcmp(name, "zygote") == 0 || strcmp(name, "zygote64") == 0) return true;
  if (strcmp(name, "usap32") == 0 || strcmp(name, "usap64") == 0) return true;
  return false;
}

// system_server and the other privileged processes must keep the real values,
// so only app-uid processes are considered. The cmdline is checked because a
// shared-uid app can hold a system uid in some setups.
static bool compute_exempt(bool* is_zygote) {
  *is_zygote = false;

  char name[256];
  if (!read_cmdline_name(name, sizeof(name)) || name[0] == '\0') {
    *is_zygote = true;
    return true;
  }

  if (name_is_zygote(name)) {
    *is_zygote = true;
    return true;
  }

  return false;
}

static bool is_exempt_process() {
  static _Atomic(pid_t) cached_pid = -1;
  static _Atomic(bool) cached_value = false;
  pid_t cur = getpid();
  if (atomic_load_explicit(&cached_pid, memory_order_acquire) == cur) {
    return atomic_load_explicit(&cached_value, memory_order_relaxed);
  }

  bool is_zygote = false;
  bool result = compute_exempt(&is_zygote);
  if (!is_zygote) {
    atomic_store_explicit(&cached_value, result, memory_order_relaxed);
    atomic_store_explicit(&cached_pid, cur, memory_order_release);
  }
  return result;
}

static bool is_app_process() {
  if ((getuid() % AID_USER_OFFSET) < AID_APP_START) return false;
  if (is_exempt_process()) return false;
  return true;
}

// Dynamic prop overrides are only meant for DroidGuard, mirroring PIFork's scope.
// The process name is only final once ActivityThread has called Process.setArgV0(),
// before that cmdline still reads "zygote*" or "<pre-initialized>". Only cache
// once it is final so an early read can't pin the wrong answer for this pid.
#define DROIDGUARD_PROCESS_NAME "com.google.android.gms.unstable"

static bool compute_droidguard(bool* resolved) {
  *resolved = false;

  char cmdline[256];
  if (!read_cmdline_name(cmdline, sizeof(cmdline))) return false;

  if (strncmp(cmdline, "zygote", 6) == 0 || strcmp(cmdline, "<pre-initialized>") == 0) {
    return false;
  }
  if (cmdline[0] == '\0') return false;

  *resolved = true;
  return strcmp(cmdline, DROIDGUARD_PROCESS_NAME) == 0;
}

static bool is_droidguard_process() {
  static _Atomic(pid_t) cached_pid = -1;
  static _Atomic(bool) cached_value = false;

  pid_t cur = getpid();
  if (atomic_load_explicit(&cached_pid, memory_order_acquire) == cur) {
    return atomic_load_explicit(&cached_value, memory_order_acquire);
  }

  bool resolved = false;
  bool result = compute_droidguard(&resolved);
  if (resolved) {
    atomic_store_explicit(&cached_value, result, memory_order_release);
    atomic_store_explicit(&cached_pid, cur, memory_order_release);
  }
  return result;
}

// Props that would name the ROM, hidden from every app process.
static const char* const kSpoofedEmptyProps[] = {
    "ro.evolution.version", "ro.evolution.build.version", "ro.evolution.display.version",
    "ro.lineage.version", "ro.lineage.build.version", "ro.cm.build.version",
    "ro.modversion", nullptr
};

struct PropOverride {
  const char* name;
  const char* value;
};

// Fixed identity as stock reports it. App processes only (see is_app_process()), so
// system_server's checks still see the real state.
static const PropOverride kSpoofedValueProps[] = {
    {"ro.debuggable", "0"},
    {"ro.build.type", "user"},
    {"ro.build.tags", "release-keys"},
    {"ro.system.build.type", "user"},
    {"ro.system.build.tags", "release-keys"},
    {"ro.vendor.build.type", "user"},
    {"ro.vendor.build.tags", "release-keys"},
    {"ro.secure", "1"},
    {"ro.adb.secure", "1"},
    // Boot state as stock reports it on a locked device.
    {"ro.boot.verifiedbootstate", "green"},
    {"vendor.boot.verifiedbootstate", "green"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"vendor.boot.vbmeta.device_state", "locked"},
    {"ro.boot.flash.locked", "1"},
    {"ro.boot.veritymode", "enforcing"},
    {"ro.secureboot.lockstate", "locked"},
    {nullptr, nullptr}
};

// Read-only keys that mirror whatever AxSpoofManager staged into the matching
// persist.sys.pif.* prop after a fingerprint refresh. Unlike kSpoofedValueProps
// these have no fixed value, are read at call time, only apply when the staging
// prop is actually set (empty = no PIF config loaded yet, so don't blank out the
// real device identity), and are only served to the DroidGuard process.
struct DynamicPropOverride {
  const char* name;
  const char* staging_name;
};
static const DynamicPropOverride kDynamicProductProps[] = {
    {"ro.product.manufacturer", "persist.sys.pif.product.manufacturer"},
    {"ro.product.brand", "persist.sys.pif.product.brand"},
    {"ro.product.model", "persist.sys.pif.product.model"},
    {"ro.product.device", "persist.sys.pif.product.device"},
    {"ro.product.name", "persist.sys.pif.product.name"},
    {"ro.product.system.manufacturer", "persist.sys.pif.product.manufacturer"},
    {"ro.product.system.brand", "persist.sys.pif.product.brand"},
    {"ro.product.system.model", "persist.sys.pif.product.model"},
    {"ro.product.vendor.manufacturer", "persist.sys.pif.product.manufacturer"},
    {"ro.product.vendor.brand", "persist.sys.pif.product.brand"},
    {"ro.product.vendor.model", "persist.sys.pif.product.model"},
    {"ro.build.product", "persist.sys.pif.product.device"},
    {"ro.build.description", "persist.sys.pif.build.description"},
    {"ro.build.flavor", "persist.sys.pif.build.flavor"},
    {nullptr, nullptr}
};

// ro.product.<partition>.<field> for every partition, served from the same staged
// product identity. A stock Pixel reports one identity on all of them, and the
// ROM's own device and name would otherwise show through on the partitions the
// table above doesn't list.
static const char* find_product_partition_staging(const char* name) {
  static const char kPrefix[] = "ro.product.";
  if (strncmp(name, kPrefix, sizeof(kPrefix) - 1) != 0) return nullptr;
  const char* partition = name + sizeof(kPrefix) - 1;
  const char* dot = partition;
  while (*dot && *dot != '.') ++dot;
  if (dot == partition || *dot != '.') return nullptr;  // needs "<partition>.<field>"
  const char* field = dot + 1;
  for (const char* c = field; *c; ++c) {
    if (*c == '.') return nullptr;
  }
  if (strcmp(field, "manufacturer") == 0) return "persist.sys.pif.product.manufacturer";
  if (strcmp(field, "brand") == 0) return "persist.sys.pif.product.brand";
  if (strcmp(field, "model") == 0) return "persist.sys.pif.product.model";
  if (strcmp(field, "device") == 0) return "persist.sys.pif.product.device";
  if (strcmp(field, "name") == 0) return "persist.sys.pif.product.name";
  return nullptr;
}

// PIFork's leading-* wildcard properties: every read-only prop ending in the
// suffix is served the same staged value, so partitions the table above would
// have to list one by one are covered as well. Only "ro." keys match, which also
// keeps the persist.sys.pif.* staging props themselves out of the match, since
// they end in these suffixes too.
struct DynamicSuffixOverride {
  const char* suffix;
  size_t suffix_len;
  const char* staging_name;
};
#define DYNAMIC_SUFFIX(suffix, staging) \
  { suffix, sizeof(suffix) - 1, staging }
static const DynamicSuffixOverride kDynamicSuffixProps[] = {
    DYNAMIC_SUFFIX(".build.id", "persist.sys.pif.build.id"),
    DYNAMIC_SUFFIX(".security_patch", "persist.sys.pif.security_patch"),
    DYNAMIC_SUFFIX("api_level", "persist.sys.pif.api_level"),
    // ro.build.version.real_security_patch, which ".security_patch" does not reach.
    DYNAMIC_SUFFIX(".real_security_patch", "persist.sys.pif.security_patch"),
    // The build type and tags of the partitions kSpoofedValueProps doesn't pin.
    DYNAMIC_SUFFIX(".build.type", "persist.sys.pif.build.type"),
    DYNAMIC_SUFFIX(".build.tags", "persist.sys.pif.build.tags"),
    {nullptr, 0, nullptr}
};

static const DynamicSuffixOverride* find_dynamic_suffix_override(const char* name) {
  if (strncmp(name, "ro.", 3) != 0) return nullptr;
  size_t len = strlen(name);
  for (const DynamicSuffixOverride* o = kDynamicSuffixProps; o->suffix; ++o) {
    if (len > o->suffix_len && strcmp(name + len - o->suffix_len, o->suffix) == 0) return o;
  }
  return nullptr;
}

// The staging props only exist to feed the DroidGuard overrides above. Hide them
// from every other app process so a plain getprop can't reveal them; the override
// lookup itself runs inside DroidGuard and still reads them.
#define PIF_STAGING_PROP_PREFIX "persist.sys.pif."

static bool is_hidden_staging_prop(const char* name) {
  return strncmp(name, PIF_STAGING_PROP_PREFIX, sizeof(PIF_STAGING_PROP_PREFIX) - 1) == 0 &&
         !is_droidguard_process();
}

// Entries from the PIF config that the tables above don't cover: exact property
// names and leading-* suffix wildcards, like PIFork's jsonProps. AxSpoofManager
// stages them as persist.sys.pif.x.<i> = "name=value" ("*suffix=value" for a
// wildcard), sorted by key, with persist.sys.pif.x.count saying how many slots
// are live. Keep the names and the slot limit in sync with AxSpoofManager.
#define PIF_CUSTOM_COUNT_PROP "persist.sys.pif.x.count"
#define PIF_CUSTOM_SLOT_PREFIX "persist.sys.pif.x."
#define PIF_CUSTOM_SLOT_MAX 32

static const char* find_custom_prop_override(const char* name, char* buffer, bool wildcard) {
  if (strncmp(name, PIF_STAGING_PROP_PREFIX, sizeof(PIF_STAGING_PROP_PREFIX) - 1) == 0) {
    return nullptr;
  }
  char raw[PROP_VALUE_MAX];
  if (__system_property_get(PIF_CUSTOM_COUNT_PROP, raw) <= 0) return nullptr;
  int count = 0;
  for (const char* c = raw; *c >= '0' && *c <= '9' && count < 1000; ++c) {
    count = count * 10 + (*c - '0');
  }
  if (count > PIF_CUSTOM_SLOT_MAX) count = PIF_CUSTOM_SLOT_MAX;

  const size_t name_len = strlen(name);
  char slot[sizeof(PIF_CUSTOM_SLOT_PREFIX) + 3];
  memcpy(slot, PIF_CUSTOM_SLOT_PREFIX, sizeof(PIF_CUSTOM_SLOT_PREFIX) - 1);
  for (int i = 0; i < count; ++i) {
    char* p = slot + sizeof(PIF_CUSTOM_SLOT_PREFIX) - 1;
    if (i >= 10) *p++ = static_cast<char>('0' + i / 10);
    *p++ = static_cast<char>('0' + i % 10);
    *p = '\0';

    char entry[PROP_VALUE_MAX];
    if (__system_property_get(slot, entry) <= 0) continue;
    char* eq = entry;
    while (*eq && *eq != '=') ++eq;
    if (*eq != '=') continue;
    *eq = '\0';
    const char* key = entry;
    const char* value = eq + 1;

    bool match;
    if (key[0] == '*') {
      if (!wildcard) continue;
      const size_t suffix_len = strlen(key + 1);
      match = suffix_len > 0 && name_len >= suffix_len &&
              strcmp(name + name_len - suffix_len, key + 1) == 0;
    } else {
      if (wildcard) continue;
      match = strcmp(key, name) == 0;
    }
    if (!match) continue;
    strcpy(buffer, value);
    return buffer;
  }
  return nullptr;
}

bool custom_rom_hide_is_app_process() {
  return is_app_process();
}

bool custom_rom_hide_should_spoof_prop(const char* name, char* value) {
  if (!name || !value) return false;
  if (reinterpret_cast<uintptr_t>(name) < 0x1000000) return false;
  if (reinterpret_cast<uintptr_t>(value) < 0x1000000) return false;
  if (!is_app_process()) return false;
  if (is_hidden_staging_prop(name)) {
    value[0] = '\0';
    return true;
  }
  for (const char* const* p = kSpoofedEmptyProps; *p; ++p) {
    if (strcmp(name, *p) == 0) {
      value[0] = '\0';
      return true;
    }
  }
  for (const PropOverride* o = kSpoofedValueProps; o->name; ++o) {
    if (strcmp(name, o->name) == 0) {
      strcpy(value, o->value);
      return true;
    }
  }
  return false;
}

bool custom_rom_hide_should_hide_prop(const char* name) {
  if (!name || reinterpret_cast<uintptr_t>(name) < 0x1000000) return false;
  if (!is_app_process()) return false;
  if (is_hidden_staging_prop(name)) return true;
  for (const char* const* p = kSpoofedEmptyProps; *p; ++p) {
    if (strcmp(name, *p) == 0) return true;
  }
  return false;
}

const char* custom_rom_hide_get_prop_override(const char* name, char* buffer) {
  if (!name || reinterpret_cast<uintptr_t>(name) < 0x1000000) return nullptr;
  if (!is_app_process()) return nullptr;
  const bool droidguard = is_droidguard_process();
  // An exact entry from the PIF config wins over everything below, as in PIFork.
  if (droidguard) {
    if (const char* v = find_custom_prop_override(name, buffer, false)) return v;
  }
  for (const PropOverride* o = kSpoofedValueProps; o->name; ++o) {
    if (strcmp(name, o->name) == 0) return o->value;
  }
  for (const DynamicPropOverride* o = kDynamicProductProps; o->name; ++o) {
    if (strcmp(name, o->name) == 0) {
      if (!droidguard) return nullptr;
      int len = __system_property_get(o->staging_name, buffer);
      if (len > 0) return buffer;
      return nullptr;  // staging prop unset, leave the real value alone
    }
  }
  if (const char* staging = find_product_partition_staging(name)) {
    if (!droidguard) return nullptr;
    int len = __system_property_get(staging, buffer);
    if (len > 0) return buffer;
    return nullptr;
  }
  if (const DynamicSuffixOverride* o = find_dynamic_suffix_override(name)) {
    if (!droidguard) return nullptr;
    int len = __system_property_get(o->staging_name, buffer);
    if (len > 0) return buffer;
  }
  // Wildcard entries from the PIF config apply last, after the fixed tables.
  if (droidguard) return find_custom_prop_override(name, buffer, true);
  return nullptr;
}