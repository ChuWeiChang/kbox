/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <string.h>

#include "kbox/identity.h"
#include "test-runner.h"

static void test_hash_username_deterministic(void)
{
    uint32_t h1 = kbox_hash_username("alice");
    uint32_t h2 = kbox_hash_username("alice");
    ASSERT_EQ(h1, h2);
}

static void test_hash_username_different(void)
{
    uint32_t h1 = kbox_hash_username("alice");
    uint32_t h2 = kbox_hash_username("bob");
    ASSERT_NE(h1, h2);
}

static void test_normalized_tmp(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/tmp", &mode, &uid, &gid));
    ASSERT_EQ(mode, 01777);
    ASSERT_EQ(uid, 0);
    ASSERT_EQ(gid, 0);
}

static void test_normalized_proc(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/proc", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0555);
}

static void test_normalized_sys(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/sys", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0555);
}

static void test_normalized_etc_passwd(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/etc/passwd", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0644);
}

static void test_normalized_etc_shadow(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/etc/shadow", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0640);
}

static void test_normalized_dev_null(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/dev/null", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0666);
}

static void test_normalized_dev_tty(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/dev/tty", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0666);
    ASSERT_EQ(gid, 5);
}

static void test_normalized_bin(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/usr/bin/ls", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0755);
}

static void test_normalized_setuid(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(
        kbox_normalized_permissions("/usr/bin/passwd", &mode, &uid, &gid));
    ASSERT_EQ(mode, 04755);
}

static void test_normalized_home_user(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/home/alice", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0700);
    ASSERT_TRUE(uid >= 1000);
    ASSERT_EQ(uid, gid);
}

static void test_normalized_root_home(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(kbox_normalized_permissions("/root", &mode, &uid, &gid));
    ASSERT_EQ(mode, 0700);
    ASSERT_EQ(uid, 0);
}

static void test_normalized_unknown_path(void)
{
    uint32_t mode, uid, gid;
    ASSERT_TRUE(
        !kbox_normalized_permissions("/random/unknown", &mode, &uid, &gid));
}

static void test_parse_change_id_valid(void)
{
    uid_t uid;
    gid_t gid;
    ASSERT_EQ(kbox_parse_change_id("1000:1000", &uid, &gid), 0);
    ASSERT_EQ(uid, 1000);
    ASSERT_EQ(gid, 1000);
}

static void test_parse_change_id_zero(void)
{
    uid_t uid;
    gid_t gid;
    ASSERT_EQ(kbox_parse_change_id("0:0", &uid, &gid), 0);
    ASSERT_EQ(uid, 0);
    ASSERT_EQ(gid, 0);
}

void test_identity_init(void)
{
    TEST_REGISTER(test_hash_username_deterministic);
    TEST_REGISTER(test_hash_username_different);
    TEST_REGISTER(test_normalized_tmp);
    TEST_REGISTER(test_normalized_proc);
    TEST_REGISTER(test_normalized_sys);
    TEST_REGISTER(test_normalized_etc_passwd);
    TEST_REGISTER(test_normalized_etc_shadow);
    TEST_REGISTER(test_normalized_dev_null);
    TEST_REGISTER(test_normalized_dev_tty);
    TEST_REGISTER(test_normalized_bin);
    TEST_REGISTER(test_normalized_setuid);
    TEST_REGISTER(test_normalized_home_user);
    TEST_REGISTER(test_normalized_root_home);
    TEST_REGISTER(test_normalized_unknown_path);
    TEST_REGISTER(test_parse_change_id_valid);
    TEST_REGISTER(test_parse_change_id_zero);
}
