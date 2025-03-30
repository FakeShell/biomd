/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef INTROSPECT_H
#define INTROSPECT_H

static const gchar biomd_introspection_xml[] =
  "<node>"
  "  <interface name='io.FuriOS.Biomd'>"
  "    <method name='GetSupportedModules'>"
  "      <arg type='as' name='modules' direction='out'/>"
  "    </method>"
  "    <method name='Ping'>"
  "      <arg type='b' name='result' direction='out'/>"
  "    </method>"
  "  </interface>"
  "</node>";

static const gchar fingerprint_introspection_xml[] =
  "<node>"
  "  <interface name='io.FuriOS.Biomd.Fingerprint'>"
  "    <method name='Enroll'>"
  "      <arg type='s' name='finger_name' direction='in'/>"
  "      <arg type='b' name='success' direction='out'/>"
  "    </method>"
  "    <method name='Identify'>"
  "      <arg type='b' name='success' direction='out'/>"
  "    </method>"
  "    <method name='StopEnroll'>"
  "      <arg type='b' name='success' direction='out'/>"
  "    </method>"
  "    <method name='StopIdentify'>"
  "      <arg type='b' name='success' direction='out'/>"
  "    </method>"
  "    <method name='RemoveFinger'>"
  "      <arg type='s' name='finger_name' direction='in'/>"
  "      <arg type='b' name='success' direction='out'/>"
  "    </method>"
  "    <method name='RenameFinger'>"
  "      <arg type='s' name='old_name' direction='in'/>"
  "      <arg type='s' name='new_name' direction='in'/>"
  "      <arg type='b' name='success' direction='out'/>"
  "    </method>"
  "    <property name='State' type='i' access='read'/>"
  "    <property name='EnrollmentProgress' type='i' access='read'/>"
  "    <property name='EnrolledFingers' type='as' access='read'/>"
  "    <property name='ErrorInfo' type='i' access='read'/>"
  "    <property name='AcquisitionInfo' type='i' access='read'/>"
  "    <property name='HardwareAvailable' type='b' access='read'/>"
  "    <property name='ValidFingerNames' type='as' access='read'/>"
  "    <signal name='StateChanged'>"
  "      <arg type='i' name='state'/>"
  "    </signal>"
  "    <signal name='EnrollmentProgressChanged'>"
  "      <arg type='i' name='progress'/>"
  "    </signal>"
  "    <signal name='EnrolledFingersChanged'>"
  "      <arg type='as' name='fingers'/>"
  "    </signal>"
  "    <signal name='ErrorInfoChanged'>"
  "      <arg type='i' name='error'/>"
  "    </signal>"
  "    <signal name='AcquisitionInfoChanged'>"
  "      <arg type='i' name='info'/>"
  "    </signal>"
  "    <signal name='Identified'>"
  "      <arg type='s' name='finger_name'/>"
  "    </signal>"
  "  </interface>"
  "</node>";

#endif /* INTROSPECT_H */
