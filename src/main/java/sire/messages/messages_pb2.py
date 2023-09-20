# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: messages.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='messages.proto',
  package='sire.messages',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0emessages.proto\x12\rsire.messages\x1a\x1fgoogle/protobuf/timestamp.proto\"G\n\x0cProtoSchnorr\x12\r\n\x05sigma\x18\x01 \x01(\x0c\x12\x12\n\nsignPubKey\x18\x02 \x01(\x0c\x12\x14\n\x0crandomPubKey\x18\x03 \x01(\x0c\"Z\n\rProtoEvidence\x12\x0e\n\x06\x61nchor\x18\x01 \x01(\x0c\x12\x13\n\x0bwatzVersion\x18\x02 \x01(\t\x12\r\n\x05\x63laim\x18\x03 \x01(\x0c\x12\x15\n\rservicePubKey\x18\x04 \x01(\x0c\"\xbc\x06\n\x0cProxyMessage\x12\x38\n\toperation\x18\x01 \x01(\x0e\x32%.sire.messages.ProxyMessage.Operation\x12.\n\x08\x65vidence\x18\x02 \x01(\x0b\x32\x1c.sire.messages.ProtoEvidence\x12\x11\n\ttimestamp\x18\x03 \x01(\x0c\x12.\n\tsignature\x18\x04 \x01(\x0b\x32\x1b.sire.messages.ProtoSchnorr\x12\x0b\n\x03key\x18\x05 \x01(\t\x12\r\n\x05value\x18\x06 \x01(\x0c\x12\x0f\n\x07oldData\x18\x07 \x01(\x0c\x12\x10\n\x08\x64\x65viceId\x18\x08 \x01(\t\x12\r\n\x05\x61ppId\x18\t \x01(\t\x12\x0c\n\x04\x63ode\x18\n \x01(\t\x12\x37\n\x06policy\x18\x0b \x01(\x0b\x32\'.sire.messages.ProxyMessage.ProtoPolicy\x12\x32\n\ndeviceType\x18\x0c \x01(\x0e\x32\x1e.sire.messages.ProtoDeviceType\x12\x0e\n\x06pubKey\x18\r \x01(\x0c\x12\r\n\x05theta\x18\x0e \x03(\x01\x12\x0f\n\x07latency\x18\x0f \x01(\x01\x1a+\n\x0bProtoPolicy\x12\x0e\n\x06policy\x18\x01 \x01(\t\x12\x0c\n\x04type\x18\x02 \x01(\x08\"\xd8\x02\n\tOperation\x12\x19\n\x15\x41TTEST_GET_PUBLIC_KEY\x10\x00\x12\x14\n\x10\x41TTEST_TIMESTAMP\x10\x01\x12\x0b\n\x07MAP_PUT\x10\x02\x12\x0e\n\nMAP_DELETE\x10\x03\x12\x0b\n\x07MAP_GET\x10\x04\x12\x0c\n\x08MAP_LIST\x10\x05\x12\x0b\n\x07MAP_CAS\x10\x06\x12\x13\n\x0fMEMBERSHIP_JOIN\x10\x07\x12\x14\n\x10MEMBERSHIP_LEAVE\x10\x08\x12\x13\n\x0fMEMBERSHIP_VIEW\x10\t\x12\x13\n\x0fMEMBERSHIP_PING\x10\n\x12\x11\n\rEXTENSION_ADD\x10\x0b\x12\x14\n\x10\x45XTENSION_REMOVE\x10\x0c\x12\x11\n\rEXTENSION_GET\x10\r\x12\x0e\n\nPOLICY_ADD\x10\x0e\x12\x11\n\rPOLICY_REMOVE\x10\x0f\x12\x0e\n\nPOLICY_GET\x10\x10\x12\x11\n\rTIMESTAMP_GET\x10\x11\"\xcf\x04\n\rProxyResponse\x12\x37\n\x04type\x18\x01 \x01(\x0e\x32).sire.messages.ProxyResponse.ResponseType\x12\x0c\n\x04list\x18\x02 \x03(\x0c\x12\r\n\x05value\x18\x03 \x01(\x0c\x12@\n\x07members\x18\x04 \x03(\x0b\x32/.sire.messages.ProxyResponse.ProtoDeviceContext\x12\x11\n\textPolicy\x18\x05 \x01(\t\x12)\n\x04sign\x18\x06 \x01(\x0b\x32\x1b.sire.messages.ProtoSchnorr\x12\x11\n\ttimestamp\x18\x07 \x01(\x0c\x12\x0e\n\x06pubKey\x18\x08 \x01(\x0c\x12\x0c\n\x04hash\x18\t \x01(\x0c\x12\x10\n\x08\x64\x65viceId\x18\n \x01(\t\x1a\xb5\x01\n\x12ProtoDeviceContext\x12\x10\n\x08\x64\x65viceId\x18\x01 \x01(\t\x12(\n\x04time\x18\x02 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x32\n\ndeviceType\x18\x03 \x01(\x0e\x32\x1e.sire.messages.ProtoDeviceType\x12/\n\x0b\x63\x65rtExpTime\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\"m\n\x0cResponseType\x12\x0b\n\x07MAP_GET\x10\x00\x12\x0c\n\x08MAP_LIST\x10\x01\x12\x08\n\x04VIEW\x10\x02\x12\x11\n\rEXTENSION_GET\x10\x03\x12\x0e\n\nPOLICY_GET\x10\x04\x12\x0b\n\x07PREJOIN\x10\x05\x12\x08\n\x04JOIN\x10\x06*g\n\x0fProtoDeviceType\x12\n\n\x06\x43\x41MERA\x10\x00\x12\x0f\n\x0bTHERMOMETER\x10\x01\x12\t\n\x05RADAR\x10\x02\x12\t\n\x05LIDAR\x10\x03\x12\x10\n\x0cMOTIONSENSOR\x10\x04\x12\x0f\n\x0bLIGHTSENSOR\x10\x05\x62\x06proto3'
  ,
  dependencies=[google_dot_protobuf_dot_timestamp__pb2.DESCRIPTOR,])

_PROTODEVICETYPE = _descriptor.EnumDescriptor(
  name='ProtoDeviceType',
  full_name='sire.messages.ProtoDeviceType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='CAMERA', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='THERMOMETER', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='RADAR', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='LIDAR', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MOTIONSENSOR', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='LIGHTSENSOR', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1656,
  serialized_end=1759,
)
_sym_db.RegisterEnumDescriptor(_PROTODEVICETYPE)

ProtoDeviceType = enum_type_wrapper.EnumTypeWrapper(_PROTODEVICETYPE)
CAMERA = 0
THERMOMETER = 1
RADAR = 2
LIDAR = 3
MOTIONSENSOR = 4
LIGHTSENSOR = 5


_PROXYMESSAGE_OPERATION = _descriptor.EnumDescriptor(
  name='Operation',
  full_name='sire.messages.ProxyMessage.Operation',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='ATTEST_GET_PUBLIC_KEY', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ATTEST_TIMESTAMP', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MAP_PUT', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MAP_DELETE', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MAP_GET', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MAP_LIST', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MAP_CAS', index=6, number=6,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MEMBERSHIP_JOIN', index=7, number=7,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MEMBERSHIP_LEAVE', index=8, number=8,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MEMBERSHIP_VIEW', index=9, number=9,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MEMBERSHIP_PING', index=10, number=10,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='EXTENSION_ADD', index=11, number=11,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='EXTENSION_REMOVE', index=12, number=12,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='EXTENSION_GET', index=13, number=13,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POLICY_ADD', index=14, number=14,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POLICY_REMOVE', index=15, number=15,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POLICY_GET', index=16, number=16,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='TIMESTAMP_GET', index=17, number=17,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=716,
  serialized_end=1060,
)
_sym_db.RegisterEnumDescriptor(_PROXYMESSAGE_OPERATION)

_PROXYRESPONSE_RESPONSETYPE = _descriptor.EnumDescriptor(
  name='ResponseType',
  full_name='sire.messages.ProxyResponse.ResponseType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='MAP_GET', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='MAP_LIST', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='VIEW', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='EXTENSION_GET', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='POLICY_GET', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PREJOIN', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='JOIN', index=6, number=6,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1545,
  serialized_end=1654,
)
_sym_db.RegisterEnumDescriptor(_PROXYRESPONSE_RESPONSETYPE)


_PROTOSCHNORR = _descriptor.Descriptor(
  name='ProtoSchnorr',
  full_name='sire.messages.ProtoSchnorr',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='sigma', full_name='sire.messages.ProtoSchnorr.sigma', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signPubKey', full_name='sire.messages.ProtoSchnorr.signPubKey', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='randomPubKey', full_name='sire.messages.ProtoSchnorr.randomPubKey', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=66,
  serialized_end=137,
)


_PROTOEVIDENCE = _descriptor.Descriptor(
  name='ProtoEvidence',
  full_name='sire.messages.ProtoEvidence',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='anchor', full_name='sire.messages.ProtoEvidence.anchor', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='watzVersion', full_name='sire.messages.ProtoEvidence.watzVersion', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='claim', full_name='sire.messages.ProtoEvidence.claim', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='servicePubKey', full_name='sire.messages.ProtoEvidence.servicePubKey', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=139,
  serialized_end=229,
)


_PROXYMESSAGE_PROTOPOLICY = _descriptor.Descriptor(
  name='ProtoPolicy',
  full_name='sire.messages.ProxyMessage.ProtoPolicy',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='policy', full_name='sire.messages.ProxyMessage.ProtoPolicy.policy', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='type', full_name='sire.messages.ProxyMessage.ProtoPolicy.type', index=1,
      number=2, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=670,
  serialized_end=713,
)

_PROXYMESSAGE = _descriptor.Descriptor(
  name='ProxyMessage',
  full_name='sire.messages.ProxyMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='operation', full_name='sire.messages.ProxyMessage.operation', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='evidence', full_name='sire.messages.ProxyMessage.evidence', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='sire.messages.ProxyMessage.timestamp', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signature', full_name='sire.messages.ProxyMessage.signature', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='key', full_name='sire.messages.ProxyMessage.key', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='sire.messages.ProxyMessage.value', index=5,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='oldData', full_name='sire.messages.ProxyMessage.oldData', index=6,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='deviceId', full_name='sire.messages.ProxyMessage.deviceId', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='appId', full_name='sire.messages.ProxyMessage.appId', index=8,
      number=9, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='code', full_name='sire.messages.ProxyMessage.code', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='policy', full_name='sire.messages.ProxyMessage.policy', index=10,
      number=11, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='deviceType', full_name='sire.messages.ProxyMessage.deviceType', index=11,
      number=12, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pubKey', full_name='sire.messages.ProxyMessage.pubKey', index=12,
      number=13, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='theta', full_name='sire.messages.ProxyMessage.theta', index=13,
      number=14, type=1, cpp_type=5, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='latency', full_name='sire.messages.ProxyMessage.latency', index=14,
      number=15, type=1, cpp_type=5, label=1,
      has_default_value=False, default_value=float(0),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_PROXYMESSAGE_PROTOPOLICY, ],
  enum_types=[
    _PROXYMESSAGE_OPERATION,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=232,
  serialized_end=1060,
)


_PROXYRESPONSE_PROTODEVICECONTEXT = _descriptor.Descriptor(
  name='ProtoDeviceContext',
  full_name='sire.messages.ProxyResponse.ProtoDeviceContext',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='deviceId', full_name='sire.messages.ProxyResponse.ProtoDeviceContext.deviceId', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='time', full_name='sire.messages.ProxyResponse.ProtoDeviceContext.time', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='deviceType', full_name='sire.messages.ProxyResponse.ProtoDeviceContext.deviceType', index=2,
      number=3, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='certExpTime', full_name='sire.messages.ProxyResponse.ProtoDeviceContext.certExpTime', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1362,
  serialized_end=1543,
)

_PROXYRESPONSE = _descriptor.Descriptor(
  name='ProxyResponse',
  full_name='sire.messages.ProxyResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='sire.messages.ProxyResponse.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='list', full_name='sire.messages.ProxyResponse.list', index=1,
      number=2, type=12, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='sire.messages.ProxyResponse.value', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='members', full_name='sire.messages.ProxyResponse.members', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='extPolicy', full_name='sire.messages.ProxyResponse.extPolicy', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='sign', full_name='sire.messages.ProxyResponse.sign', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='sire.messages.ProxyResponse.timestamp', index=6,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pubKey', full_name='sire.messages.ProxyResponse.pubKey', index=7,
      number=8, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='hash', full_name='sire.messages.ProxyResponse.hash', index=8,
      number=9, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='deviceId', full_name='sire.messages.ProxyResponse.deviceId', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_PROXYRESPONSE_PROTODEVICECONTEXT, ],
  enum_types=[
    _PROXYRESPONSE_RESPONSETYPE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1063,
  serialized_end=1654,
)

_PROXYMESSAGE_PROTOPOLICY.containing_type = _PROXYMESSAGE
_PROXYMESSAGE.fields_by_name['operation'].enum_type = _PROXYMESSAGE_OPERATION
_PROXYMESSAGE.fields_by_name['evidence'].message_type = _PROTOEVIDENCE
_PROXYMESSAGE.fields_by_name['signature'].message_type = _PROTOSCHNORR
_PROXYMESSAGE.fields_by_name['policy'].message_type = _PROXYMESSAGE_PROTOPOLICY
_PROXYMESSAGE.fields_by_name['deviceType'].enum_type = _PROTODEVICETYPE
_PROXYMESSAGE_OPERATION.containing_type = _PROXYMESSAGE
_PROXYRESPONSE_PROTODEVICECONTEXT.fields_by_name['time'].message_type = google_dot_protobuf_dot_timestamp__pb2._TIMESTAMP
_PROXYRESPONSE_PROTODEVICECONTEXT.fields_by_name['deviceType'].enum_type = _PROTODEVICETYPE
_PROXYRESPONSE_PROTODEVICECONTEXT.fields_by_name['certExpTime'].message_type = google_dot_protobuf_dot_timestamp__pb2._TIMESTAMP
_PROXYRESPONSE_PROTODEVICECONTEXT.containing_type = _PROXYRESPONSE
_PROXYRESPONSE.fields_by_name['type'].enum_type = _PROXYRESPONSE_RESPONSETYPE
_PROXYRESPONSE.fields_by_name['members'].message_type = _PROXYRESPONSE_PROTODEVICECONTEXT
_PROXYRESPONSE.fields_by_name['sign'].message_type = _PROTOSCHNORR
_PROXYRESPONSE_RESPONSETYPE.containing_type = _PROXYRESPONSE
DESCRIPTOR.message_types_by_name['ProtoSchnorr'] = _PROTOSCHNORR
DESCRIPTOR.message_types_by_name['ProtoEvidence'] = _PROTOEVIDENCE
DESCRIPTOR.message_types_by_name['ProxyMessage'] = _PROXYMESSAGE
DESCRIPTOR.message_types_by_name['ProxyResponse'] = _PROXYRESPONSE
DESCRIPTOR.enum_types_by_name['ProtoDeviceType'] = _PROTODEVICETYPE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ProtoSchnorr = _reflection.GeneratedProtocolMessageType('ProtoSchnorr', (_message.Message,), {
  'DESCRIPTOR' : _PROTOSCHNORR,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:sire.messages.ProtoSchnorr)
  })
_sym_db.RegisterMessage(ProtoSchnorr)

ProtoEvidence = _reflection.GeneratedProtocolMessageType('ProtoEvidence', (_message.Message,), {
  'DESCRIPTOR' : _PROTOEVIDENCE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:sire.messages.ProtoEvidence)
  })
_sym_db.RegisterMessage(ProtoEvidence)

ProxyMessage = _reflection.GeneratedProtocolMessageType('ProxyMessage', (_message.Message,), {

  'ProtoPolicy' : _reflection.GeneratedProtocolMessageType('ProtoPolicy', (_message.Message,), {
    'DESCRIPTOR' : _PROXYMESSAGE_PROTOPOLICY,
    '__module__' : 'messages_pb2'
    # @@protoc_insertion_point(class_scope:sire.messages.ProxyMessage.ProtoPolicy)
    })
  ,
  'DESCRIPTOR' : _PROXYMESSAGE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:sire.messages.ProxyMessage)
  })
_sym_db.RegisterMessage(ProxyMessage)
_sym_db.RegisterMessage(ProxyMessage.ProtoPolicy)

ProxyResponse = _reflection.GeneratedProtocolMessageType('ProxyResponse', (_message.Message,), {

  'ProtoDeviceContext' : _reflection.GeneratedProtocolMessageType('ProtoDeviceContext', (_message.Message,), {
    'DESCRIPTOR' : _PROXYRESPONSE_PROTODEVICECONTEXT,
    '__module__' : 'messages_pb2'
    # @@protoc_insertion_point(class_scope:sire.messages.ProxyResponse.ProtoDeviceContext)
    })
  ,
  'DESCRIPTOR' : _PROXYRESPONSE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:sire.messages.ProxyResponse)
  })
_sym_db.RegisterMessage(ProxyResponse)
_sym_db.RegisterMessage(ProxyResponse.ProtoDeviceContext)


# @@protoc_insertion_point(module_scope)
