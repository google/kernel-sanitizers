/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * errcap.h
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2020 Google, Inc.
 *
 */

#ifndef _LINUX_ERRCAP_H
#define _LINUX_ERRCAP_H

void errcap_start_report(void);
void errcap_stop_report(void);

#endif  // _LINUX_ERRCAP_H

