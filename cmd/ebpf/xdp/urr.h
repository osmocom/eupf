/**
 * Copyright 2023 Edgecom LLC
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

/* measurement methods */
enum meas_method_values {
   MM_DISABLED                             = 0x00,
   MM_DURATION                             = 0x01,
   MM_VOLUME                               = 0x02,
   MM_EVENT                                = 0x04,
};

/* report triggers flags */
enum rep_trig_5_mask {
   RT5_PERIODIC_REPORTING                  = 0x01,
   RT5_VOLUME_THRESHOLD                    = 0x02,
   RT5_TIME_THRESHOLD                      = 0x04,
   RT5_QUOTA_HOLDING_TIME                  = 0x08,
   RT5_START_OF_TRAFFIC                    = 0x10,
   RT5_STOP_OF_TRAFFIC                     = 0x20,
   RT5_DROPPED_DL_TRAFFIC_THRESHOLD        = 0x40,
   RT5_LINKED_USAGE_REPORTING              = 0x80,
};

enum rep_trig_6_mask {
   RT6_VOLUME_QUOTA                        = 0x01,
   RT6_TIME_QUOTA                          = 0x02,
   RT6_ENVELOPE_CLOSURE                    = 0x04,
   RT6_MAC_ADDRESSES_REPORTING             = 0x08,
   RT6_EVENT_THRESHOLD                     = 0x10,
   RT6_EVENT_QUOTA                         = 0x20,
   RT6_IP_MULTICAST_JOIN_LEAVE             = 0x40,
   RT6_QUOTA_VALIDITY_TIME                 = 0x80,
};

enum rep_trig_7_mask {
   RT7_REPORT_THE_END_MARKER_RECEPTION     = 0x01,
   RT7_USER_PLANE_INACTIVITY_TIMER         = 0x02,
};

/* measurement info */
enum meas_info_mask {
   MI_MBQE         = 0x01,      /* Measurement Before QoS Enforcement */
   MI_INAM         = 0x02,      /* Inactive Measurement */
   MI_RADI         = 0x04,      /* Reduced Application Detection Information */
   MI_ISTM         = 0x08,      /* Immediate Start Time Metering */
   MI_MNOP         = 0x10,      /* Measurement of Number of Packets */
};

/* volume threshold flags */
enum vol_thres_mask {
   VT_TOVOL        = 0x01,
   VT_ULVOL        = 0x02,
   VT_DLVOL        = 0x04,
};

struct urr_info {
    __u8 meas_method;     // bit mask: MM_..
    __u8 reptri_5;        // bit mask: RT5_..
    __u8 reptri_6;        // bit mask: RT6_..
    __u8 reptri_7;        // bit mask: RT7_..
    __u8 meas_info;       // bit mask: MI_..
    __u8 vol_threshold_flags;   // bit mask: VT_...
    __u8 vol_quota_flags;       // bit mask: VT_...
    __u8 report_sent;     // 0: expecting a report, 1: report was sent
    __u64 vol_threshold_total;
    __u64 vol_threshold_uplink;
    __u64 vol_threshold_downlink;
    __u64 vol_quota_total;
    __u64 vol_quota_uplink;
    __u64 vol_quota_downlink;
    __u32 time_threshold;    // in second
    __u32 time_quota;        // in second
    __u32 quota_validity;    // in second
    __u32 quota_holding;     // in second
};

struct urr_acc {
    __u64 total_octets;
    __u64 ul_octets;
    __u64 dl_octets;
    __u64 total_pkts;
    __u64 ul_pkts;
    __u64 dl_pkts;
    __u64 ktime_first_pkt_ns;
    __u64 ktime_last_pkt_ns;
};

enum rep_type_mask {
   RT_UP_INITIATED_SESSION_REQUEST      = 0x40,
   RT_SESSION_REPORT                    = 0x20,
   RT_TSC_MANAGEMENT_INFORMATION_REPORT = 0x10,
   RT_USER_PLANE_INACTIVITY_REPORT      = 0x08,
   RT_ERROR_INDICATION_REPORT           = 0x04,
   RT_USAGE_REPORT                      = 0x02,
   RT_DOWNLINK_DATA_REPORT              = 0x01,
};


enum usage_trig_5_mask {
   UT5_PERIODIC_REPORTING                  = 0x01,
   UT5_VOLUME_THRESHOLD                    = 0x02,
   UT5_TIME_THRESHOLD                      = 0x04,
   UT5_QUOTA_HOLDING_TIME                  = 0x08,
   UT5_START_OF_TRAFFIC                    = 0x10,
   UT5_STOP_OF_TRAFFIC                     = 0x20,
   UT5_DROPPED_DL_TRAFFIC_THRESHOLD        = 0x40,
   UT5_IMMEDTATE_REPORT                    = 0x80,
};

enum usage_trig_6_mask {
   UT6_VOLUME_QUOTA                        = 0x01,
   UT6_TIME_QUOTA                          = 0x02,
   UT6_LINKED_USAGE_REPORTING              = 0x04,
   UT6_TERMINATION_REPORT                  = 0x08,
   UT6_MONITORING_TIME                     = 0x10,
   UT6_ENVELOPE_CLOSURE                    = 0x20,
   UT6_MAC_ADDRESS_REPORTING               = 0x40,
   UT6_EVENT_THRESHOLD                     = 0x80,
};

enum usage_trig_7_mask {
   UT7_EVENT_QUOTA                         = 0x01,
   UT7_TERMINATION_BY_UP_FUNCTION_REPORT   = 0x02,
   UT7_IP_MULTICAST_JOIN_LEAVE             = 0x04,
   UT7_QUOTA_VALIDITY_TIME                 = 0x08,
   UT7_END_MARKER_RECEPTION_REPORT         = 0x10,
   UT7_USER_PLANE_INACTIVITY_TIMER         = 0x20,
};

struct urr_rep {
    __u8 type;           // bitmask: RT_...
    __u8 usage_tri_5;    // bitmask: UT5_..
    __u8 usage_tri_6;    // bitmask: UT6_..
    __u8 usage_tri_7;    // bitmask: UT7_..
    __u32 id;            // urr id to which this report applies
    __u64 total_octets;
    __u64 ul_octets;
    __u64 dl_octets;
    __u64 total_pkts;
    __u64 ul_pkts;
    __u64 dl_pkts;
    __u64 ktime_first_pkt_ns;
    __u64 ktime_last_pkt_ns;
};

#define URR_MAP_SIZE 1024

/* URR ID -> URR Info */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct urr_info);
    __uint(max_entries, URR_MAP_SIZE);
} urr_info_map SEC(".maps");

/* URR ID -> URR Acc */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct urr_acc);
    __uint(max_entries, URR_MAP_SIZE);
} urr_acc_map SEC(".maps");

/* usage report */
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} urr_rep_map SEC(".maps");
