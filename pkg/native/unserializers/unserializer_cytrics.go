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
	if bom.Hardware != nil {

	}
}


// componentToNodes takes a CycloneDX component and computes its graph fragment,
// returning a nodelist
func (u *CDX) componentToNodeList(component *cdx.Component, cc *int) (*sbom.NodeList, error) {
	node, err := u.componentToNode(component, cc)
	if err != nil {
		return nil, fmt.Errorf("converting cdx component to node: %w", err)
	}

	nl := &sbom.NodeList{
		Nodes:        []*sbom.Node{node},
		Edges:        []*sbom.Edge{},
		RootElements: []string{node.Id},
	}

	if component.Components != nil {
		for i := range *component.Components {
			subList, err := u.componentToNodeList(&(*component.Components)[i], cc)
			if err != nil {
				return nil, fmt.Errorf("converting subcomponent to nodelist: %w", err)
			}
			if err := nl.RelateNodeListAtID(subList, node.Id, sbom.Edge_contains); err != nil {
				return nil, fmt.Errorf("relating subcomponents to new node: %w", err)
			}
		}
	}

	return nl, nil
}

