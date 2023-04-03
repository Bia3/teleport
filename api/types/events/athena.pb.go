// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: teleport/legacy/types/events/athena.proto

package events

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// AthenaS3EventPayload is used as payload for sending large events to SQS.
type AthenaS3EventPayload struct {
	// Path on S3.
	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	// Custom KMS key for server-side encryption.
	Ckms                 string   `protobuf:"bytes,2,opt,name=ckms,proto3" json:"ckms,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AthenaS3EventPayload) Reset()         { *m = AthenaS3EventPayload{} }
func (m *AthenaS3EventPayload) String() string { return proto.CompactTextString(m) }
func (*AthenaS3EventPayload) ProtoMessage()    {}
func (*AthenaS3EventPayload) Descriptor() ([]byte, []int) {
	return fileDescriptor_c0d45ba0499f9acf, []int{0}
}
func (m *AthenaS3EventPayload) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AthenaS3EventPayload) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AthenaS3EventPayload.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AthenaS3EventPayload) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AthenaS3EventPayload.Merge(m, src)
}
func (m *AthenaS3EventPayload) XXX_Size() int {
	return m.Size()
}
func (m *AthenaS3EventPayload) XXX_DiscardUnknown() {
	xxx_messageInfo_AthenaS3EventPayload.DiscardUnknown(m)
}

var xxx_messageInfo_AthenaS3EventPayload proto.InternalMessageInfo

func (m *AthenaS3EventPayload) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *AthenaS3EventPayload) GetCkms() string {
	if m != nil {
		return m.Ckms
	}
	return ""
}

func init() {
	proto.RegisterType((*AthenaS3EventPayload)(nil), "events.AthenaS3EventPayload")
}

func init() {
	proto.RegisterFile("teleport/legacy/types/events/athena.proto", fileDescriptor_c0d45ba0499f9acf)
}

var fileDescriptor_c0d45ba0499f9acf = []byte{
	// 173 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x2c, 0x49, 0xcd, 0x49,
	0x2d, 0xc8, 0x2f, 0x2a, 0xd1, 0xcf, 0x49, 0x4d, 0x4f, 0x4c, 0xae, 0xd4, 0x2f, 0xa9, 0x2c, 0x48,
	0x2d, 0xd6, 0x4f, 0x2d, 0x4b, 0xcd, 0x2b, 0x29, 0xd6, 0x4f, 0x2c, 0xc9, 0x48, 0xcd, 0x4b, 0xd4,
	0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x83, 0x08, 0x2a, 0xd9, 0x71, 0x89, 0x38, 0x82, 0xc5,
	0x83, 0x8d, 0x5d, 0x41, 0x22, 0x01, 0x89, 0x95, 0x39, 0xf9, 0x89, 0x29, 0x42, 0x42, 0x5c, 0x2c,
	0x05, 0x89, 0x25, 0x19, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x9c, 0x41, 0x60, 0x36, 0x48, 0x2c, 0x39,
	0x3b, 0xb7, 0x58, 0x82, 0x09, 0x22, 0x06, 0x62, 0x3b, 0x39, 0x9c, 0x78, 0x24, 0xc7, 0x78, 0xe1,
	0x91, 0x1c, 0xe3, 0x83, 0x47, 0x72, 0x8c, 0x51, 0x46, 0xe9, 0x99, 0x25, 0x19, 0xa5, 0x49, 0x7a,
	0xc9, 0xf9, 0xb9, 0xfa, 0xe9, 0x45, 0x89, 0x65, 0x99, 0x25, 0x89, 0x25, 0x99, 0xf9, 0x79, 0x89,
	0x39, 0xfa, 0x70, 0x97, 0x25, 0x16, 0x64, 0xa2, 0x38, 0x2b, 0x89, 0x0d, 0xec, 0x20, 0x63, 0x40,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x34, 0x3f, 0xa5, 0x48, 0xbd, 0x00, 0x00, 0x00,
}

func (m *AthenaS3EventPayload) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AthenaS3EventPayload) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AthenaS3EventPayload) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Ckms) > 0 {
		i -= len(m.Ckms)
		copy(dAtA[i:], m.Ckms)
		i = encodeVarintAthena(dAtA, i, uint64(len(m.Ckms)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Path) > 0 {
		i -= len(m.Path)
		copy(dAtA[i:], m.Path)
		i = encodeVarintAthena(dAtA, i, uint64(len(m.Path)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintAthena(dAtA []byte, offset int, v uint64) int {
	offset -= sovAthena(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *AthenaS3EventPayload) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Path)
	if l > 0 {
		n += 1 + l + sovAthena(uint64(l))
	}
	l = len(m.Ckms)
	if l > 0 {
		n += 1 + l + sovAthena(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovAthena(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozAthena(x uint64) (n int) {
	return sovAthena(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *AthenaS3EventPayload) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAthena
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AthenaS3EventPayload: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AthenaS3EventPayload: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Path", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAthena
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthAthena
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAthena
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Path = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ckms", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAthena
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthAthena
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAthena
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Ckms = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAthena(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAthena
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipAthena(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowAthena
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowAthena
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowAthena
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthAthena
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupAthena
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthAthena
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthAthena        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowAthena          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupAthena = fmt.Errorf("proto: unexpected end of group")
)
