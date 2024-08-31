package unserializers

import (
	"io"
	"fmt"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/hunterA-ai/cytrics-go/cytrics"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CY struct {
	version string
	encoding string
}
type Component struct{
	*cytrics.Hardware
	*cytrics.Software
}

func NewCY(version, encoding string) *CY {
	return &CY{
		version: version,
		encoding: encoding,
	}
}

// skipping CyTRICS type declaration for now (ignore version and xml, assume json v2)
func (u *CY) Unserialize(r io.Reader, _ *native.UnserializeOptions, _ interface{}) (*sbom.Document, error) {
	// Decode the BOM
	bom := cytrics.NewBOM()
	// decoder := cytrics.NewBOMDecoder(res.Body)
	if err := bom.Load(r); err != nil {
		panic(err)
	}


	md := &sbom.Metadata{
		Id:      bom.UUID(),
		Version: bom.Version,
		Name:	 "unknown",
		Date:    &timestamppb.Timestamp{},
		Tools:   []*sbom.Tool{},
		Authors: []*sbom.Person{},
		DocumentTypes: []*sbom.DocumentType{},
	}
	
	doc := &sbom.Document{
		Metadata: md,
		NodeList: &sbom.NodeList{},
	}

	cc := 0

	// TODO: construct Metadata.DocumentTypes
	name := "name"
	desc := "desc"
	// FIXME: Add HBOM types and extract this information from the BOM
	t := sbom.DocumentType_OTHER
	md.DocumentTypes = append(md.DocumentTypes, &sbom.DocumentType{
		Name:        &name,
		Description: &desc,
		Type:        &t,
	})

	// TODO: construct Document.NodeList
		// TODO: Construct Node
	// TODO: Construct relations


	// doc.NodeList.Add(nl)
	// doc := sbom.NewDocument()
	return sbom.NewDocument(), nil
}


func (u *CY) constructNodeList(bom *cytrics.BOM) (*sbom.NodeList, error) {
	nl := &sbom.NodeList{
		Nodes:        []*sbom.Node{},
		Edges:        []*sbom.Edge{},
		RootElements: []string{},
	}

	if bom.Hardware != nil {
		for _, item := range *bom.Hardware {
			node, err := u.constructNode(&item)
			if err != nil {
				panic(err)
			}
			nl.Nodes = append(nl.Nodes, node)
		}
	}
	if bom.Software != nil {
		for _, item := range *bom.Software {
			node, err := u.constructNode(&item)
			if err != nil {
				panic(err)
			}
			nl.Nodes = append(nl.Nodes, node)
		}
	}
}


// TODO: Type component, I'm lazy so we're going with this for now because I don't
// know how to create a different node for each type of CyTRICS field... womp womp
func (u *CY) constructNode(component *Component) (*sbom.Node, error) {
	// TODO: Find more Node fields to populate
	// TODO: Fix if fields do not exist
	var UUID string
	var Name string
	if component.Hardware != nil {
		UUID = component.Hardware.UUID
		Name = component.Hardware.Name
	}
	if component.Software != nil {
		UUID = component.Software.UUID
		Name = component.Software.Name
	}
	unknownVersion := "unknown"
	node := &sbom.Node{
		Id:		UUID,
		Type:	sbom.Node_PACKAGE,
		Name:	component.Name,
		Version: 	unknownVersion,
		Licenses: []string{},
		Hashes:	map[int32]string{},
		Description: *component.Description,
		Attribution:        []string{},
		Suppliers:          []*sbom.Person{}, // TODO
		Originators:        []*sbom.Person{}, // TODO
		ExternalReferences: []*sbom.ExternalReference{},
		Identifiers:        map[int32]string{},
		FileTypes:          []string{},
	}
	return node, nil
}

// type Node struct {
// 	state         protoimpl.MessageState
// 	sizeCache     protoimpl.SizeCache
// 	unknownFields protoimpl.UnknownFields

// 	Id          string        `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`                                           // Unique identifier for the node.
// 	Type        Node_NodeType `protobuf:"varint,2,opt,name=type,proto3,enum=protobom.protobom.Node_NodeType" json:"type,omitempty"` // Type of the software component.
// 	Name        string        `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`                                       // Name of the software component.
// 	Version     string        `protobuf:"bytes,4,opt,name=version,proto3" json:"version,omitempty"`                                 // Version string of the software component.
// 	FileName    string        `protobuf:"bytes,5,opt,name=file_name,json=fileName,proto3" json:"file_name,omitempty"`               // Package filename when there is one.
// 	UrlHome     string        `protobuf:"bytes,6,opt,name=url_home,json=urlHome,proto3" json:"url_home,omitempty"`                  // Website of the package.
// 	UrlDownload string        `protobuf:"bytes,7,opt,name=url_download,json=urlDownload,proto3" json:"url_download,omitempty"`      // Location to download the package.
// 	// Multiple licenses applicable to the software component,
// 	// Multiple licenses can be specified for CycloneDX 1.4 and files in SPDX.
// 	Licenses []string `protobuf:"bytes,8,rep,name=licenses,proto3" json:"licenses,omitempty"`
// 	// Concluded license applicable to the software component,
// 	// This is only in SPDX and it is just one.
// 	LicenseConcluded string `protobuf:"bytes,9,opt,name=license_concluded,json=licenseConcluded,proto3" json:"license_concluded,omitempty"`
// 	LicenseComments  string `protobuf:"bytes,10,opt,name=license_comments,json=licenseComments,proto3" json:"license_comments,omitempty"` // Comments on the license.
// 	Copyright        string `protobuf:"bytes,11,opt,name=copyright,proto3" json:"copyright,omitempty"`                                    // Copyright information applicable to the software component.
// 	// This field is intended to capture details related to the source or origin of the software component.
// 	// It may include any relevant background information or additional comments.
// 	SourceInfo         string                 `protobuf:"bytes,13,opt,name=source_info,json=sourceInfo,proto3" json:"source_info,omitempty"`
// 	Comment            string                 `protobuf:"bytes,15,opt,name=comment,proto3" json:"comment,omitempty"`                                                 // Comments on the software component.
// 	Summary            string                 `protobuf:"bytes,16,opt,name=summary,proto3" json:"summary,omitempty"`                                                 // Concise description of the software component (short description).
// 	Description        string                 `protobuf:"bytes,17,opt,name=description,proto3" json:"description,omitempty"`                                         // Detailed description of the software component (full description).
// 	Attribution        []string               `protobuf:"bytes,18,rep,name=attribution,proto3" json:"attribution,omitempty"`                                         // One or more contributions or acknowledgments associated with the software component.
// 	Suppliers          []*Person              `protobuf:"bytes,19,rep,name=suppliers,proto3" json:"suppliers,omitempty"`                                             // One or more entities providing the software component.
// 	Originators        []*Person              `protobuf:"bytes,20,rep,name=originators,proto3" json:"originators,omitempty"`                                         // One or more entities involved in the creation or maintenance of the software component.
// 	ReleaseDate        *timestamppb.Timestamp `protobuf:"bytes,21,opt,name=release_date,json=releaseDate,proto3" json:"release_date,omitempty"`                      // Release date of the software component.
// 	BuildDate          *timestamppb.Timestamp `protobuf:"bytes,22,opt,name=build_date,json=buildDate,proto3" json:"build_date,omitempty"`                            // Build date of the software component.
// 	ValidUntilDate     *timestamppb.Timestamp `protobuf:"bytes,23,opt,name=valid_until_date,json=validUntilDate,proto3" json:"valid_until_date,omitempty"`           // Valid until date of the software component.
// 	ExternalReferences []*ExternalReference   `protobuf:"bytes,24,rep,name=external_references,json=externalReferences,proto3" json:"external_references,omitempty"` // External references associated with the software component.
// 	FileTypes          []string               `protobuf:"bytes,27,rep,name=file_types,json=fileTypes,proto3" json:"file_types,omitempty"`                            // File types associated with the component
// 	// Software identifer map used by the component.
// 	// Maps between the software identifier types and the identifier values.
// 	Identifiers map[int32]string `protobuf:"bytes,28,rep,name=identifiers,proto3" json:"identifiers,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
// 	// Hashes map associated with the software component.
// 	// Maps between hash algorithms types and hash values.
// 	Hashes         map[int32]string `protobuf:"bytes,29,rep,name=hashes,proto3" json:"hashes,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
// 	PrimaryPurpose []Purpose        `protobuf:"varint,30,rep,packed,name=primary_purpose,json=primaryPurpose,proto3,enum=protobom.protobom.Purpose" json:"primary_purpose,omitempty"` // Primary purpose or role assigned to the software component.
// }
