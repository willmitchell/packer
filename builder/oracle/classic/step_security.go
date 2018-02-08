package classic

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-oracle-terraform/compute"
	"github.com/hashicorp/packer/helper/multistep"
	"github.com/hashicorp/packer/packer"
)

type stepSecurity struct{}

func (s *stepSecurity) Run(_ context.Context, state multistep.StateBag) multistep.StepAction {
	ui := state.Get("ui").(packer.Ui)
	config := state.Get("config").(*Config)

	commType := ""
	if config.Comm.Type == "ssh" {
		commType = "SSH"
	} else if config.Comm.Type == "winrm" {
		commType = "WINRM"
	}

	ui.Say(fmt.Sprintf("Configuring security lists and rules to enable %s access...", commType))

	client := state.Get("client").(*compute.ComputeClient)

	secListName := fmt.Sprintf("/Compute-%s/%s/Packer_%s_Allow_%s",
		config.IdentityDomain, config.Username, commType, config.ImageName)
	secListClient := client.SecurityLists()
	secListInput := compute.CreateSecurityListInput{
		Description: fmt.Sprintf("Packer-generated security list to give packer %s access", commType),
		Name:        secListName,
	}
	_, err := secListClient.CreateSecurityList(&secListInput)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			err = fmt.Errorf("Error creating security List to"+
				" allow Packer to connect to Oracle instance via %s: %s", commType, err)
			ui.Error(err.Error())
			state.Put("error", err)
			return multistep.ActionHalt
		}
	}
	// DOCS NOTE: user must have Compute_Operations role
	// Create security rule that allows Packer to connect via SSH or winRM
	var application string
	if commType == "SSH" {
		application = "/oracle/public/ssh"
	} else if commType == "WINRM" {
		// Create winRM protocol; don't need to do this for SSH becasue it is
		// built into the Oracle API.
		// input := compute.CreateSecurityProtocolInput{
		// 	Name:        "WINRM",
		// 	Description: "packer-generated protocol to allow winRM communicator",
		// 	DstPortSet:  []string{"5985", "5986"}, // TODO make configurable
		// 	IPProtocol:  "tcp",
		// }
		// protocolClient := client.SecurityProtocols()
		// secProtocol, err := protocolClient.CreateSecurityProtocol()
		// if err != nil {
		// 	err = fmt.Errorf("Error creating security protocol to"+
		// 		" allow Packer to connect to Oracle instance via %s: %s", commType, err)
		// 	ui.Error(err.Error())
		// 	state.Put("error", err)
		// 	return multistep.ActionHalt
		// }

		// Create a security Applicatin defining WinRM
		applicationClient := client.SecurityApplications()
		applicationInput := compute.CreateSecurityApplicationInput{
			Description: "Allows Packer to connect to instance via winRM",
			DPort:       "5985-5986",
			Name:        "packer_winRM",
			Protocol:    "TCP",
		}
		_, err := applicationClient.CreateSecurityApplication(&applicationInput)
		if err != nil {
			err = fmt.Errorf("Error creating security application to"+
				" allow Packer to connect to Oracle instance via %s: %s", commType, err)
			ui.Error(err.Error())
			state.Put("error", err)
			return multistep.ActionHalt
		}
		application = fmt.Sprintf("/Compute-%s/%s/packer_winRM",
			config.IdentityDomain, config.Username)

		// Create Access Control List
		aclClient := client.ACLs()
		createInput := compute.CreateACLInput{
			Description: "packer winrm acl",
			Name:        "PackerWinRMACL",
		}
		_, err = aclClient.CreateACL(&createInput)
		if err != nil {
			err = fmt.Errorf("Error creating ACL to allow Packer to connect to"+
				" Oracle instance via %s: %s", commType, err)
			ui.Error(err.Error())
			state.Put("error", err)
			return multistep.ActionHalt
		}

		instanceInfo := state.Get("instance_net").(compute.InstanceInfo)
		log.Printf("MEGAN instanceInfo is %#v", instanceInfo)
		log.Printf("MEGAN vnic is %s", instanceInfo.Networking.Vnic)

		// Create vNICset
		nicSetClient := client.VirtNICSets()
		nicInput := compute.CreateVirtualNICSetInput{
			Name:        "PackerWinRM",
			Description: "allow packer to connect via winRM",
			VirtualNICs: []string{"eth0"},
			AppliedACLs: []string{fmt.Sprintf("/Compute-%s/%s/PackerWinRMACL", config.IdentityDomain, config.Username)},
		}
		nicSetClient.CreateVirtualNICSet(&nicInput)
	}
	secRulesClient := client.SecRules()
	secRulesInput := compute.CreateSecRuleInput{
		Action:          "PERMIT",
		Application:     application,
		Description:     "Packer-generated security rule to allow ssh/winrm",
		DestinationList: fmt.Sprintf("seclist:%s", secListName),
		Name:            fmt.Sprintf("Packer-allow-%s-Rule_%s", commType, config.ImageName),
		SourceList:      config.SSHSourceList,
	}

	secRuleName := fmt.Sprintf("/Compute-%s/%s/Packer-allow-%s-Rule_%s",
		config.IdentityDomain, config.Username, commType, config.ImageName)
	_, err = secRulesClient.CreateSecRule(&secRulesInput)
	if err != nil {
		log.Printf("Error creating security rule to allow %s: %s", commType, err.Error())
		if !strings.Contains(err.Error(), "already exists") {
			err = fmt.Errorf("Error creating security rule to"+
				" allow Packer to connect to Oracle instance via commType: %s", commType, err)
			ui.Error(err.Error())
			state.Put("error", err)
			return multistep.ActionHalt
		}
	}
	state.Put("security_rule_name", secRuleName)
	state.Put("security_list", secListName)
	return multistep.ActionContinue
}

func (s *stepSecurity) Cleanup(state multistep.StateBag) {
	client := state.Get("client").(*compute.ComputeClient)
	ui := state.Get("ui").(packer.Ui)
	ui.Say("Deleting temporary rules and lists...")

	// delete security rules that Packer generated
	secRuleName := state.Get("security_rule_name").(string)
	secRulesClient := client.SecRules()
	ruleInput := compute.DeleteSecRuleInput{Name: secRuleName}
	err := secRulesClient.DeleteSecRule(&ruleInput)
	if err != nil {
		ui.Say(fmt.Sprintf("Error deleting the packer-generated security rule %s; "+
			"please delete manually. (error: %s)", secRuleName, err.Error()))
	}

	// delete security list that Packer generated
	secListName := state.Get("security_list").(string)
	secListClient := client.SecurityLists()
	input := compute.DeleteSecurityListInput{Name: secListName}
	err = secListClient.DeleteSecurityList(&input)
	if err != nil {
		ui.Say(fmt.Sprintf("Error deleting the packer-generated security list %s; "+
			"please delete manually. (error : %s)", secListName, err.Error()))
	}
}
