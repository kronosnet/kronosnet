/*
 * Copyright (C) 2026 Red Hat, Inc.  All rights reserved.
 *
 * Routines for the Kronosnet (kronosnet) protocol used by corosync
 * corosync packets are NOT decoded by this dissector
 *
 * Authors: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef PACKET_KRONOSNET_H
#define PACKET_KRONOSNET_H

void proto_register_kronosnet(void);
void proto_reg_handoff_kronosnet(void);

#endif /* PACKET_KRONOSNET_H */
