package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	apiURL   string
	username string
	password string
)

func newClient() *http.Client {
	return &http.Client{}
}

func doRequest(method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(b)
	}

	req, err := http.NewRequest(method, apiURL+path, reqBody)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(username, password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := newClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

func prettyPrint(data []byte) {
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		fmt.Println(string(data))
		return
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

var rootCmd = &cobra.Command{
	Use:   "cyrber",
	Short: "CYRBER CLI — autonomous security reconnaissance",
}

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Start a full scan",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		agent, _ := cmd.Flags().GetBool("agent")
		var path string
		if agent {
			path = "/agent/start?target=" + target
			fmt.Printf("[*] Starting AGENT scan: %s\n", target)
		} else {
			path = "/scan/start?target=" + target
			fmt.Printf("[*] Starting scan: %s\n", target)
		}
		data, _, err := doRequest("GET", path, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		prettyPrint(data)
	},
}

var statusCmd = &cobra.Command{
	Use:   "status [task_id]",
	Short: "Check scan status",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		data, _, err := doRequest("GET", "/scan/status/"+args[0], nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		prettyPrint(data)
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent scans",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		data, _, err := doRequest("GET", fmt.Sprintf("/scans?limit=%d", limit), nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		var scans []map[string]interface{}
		if err := json.Unmarshal(data, &scans); err != nil {
			prettyPrint(data)
			return
		}

		fmt.Printf("%-36s  %-20s  %-8s  %s\n", "TASK ID", "TARGET", "RISK", "DATE")
		fmt.Println(strings.Repeat("-", 80))
		for _, s := range scans {
			tid := fmt.Sprintf("%v", s["task_id"])
			target := fmt.Sprintf("%v", s["target"])
			risk := fmt.Sprintf("%v", s["risk_level"])
			date := fmt.Sprintf("%v", s["created_at"])
			if len(date) > 16 {
				date = date[:16]
			}
			fmt.Printf("%-36s  %-20s  %-8s  %s\n", tid, target, risk, date)
		}
	},
}

var multiCmd = &cobra.Command{
	Use:   "multi [target1] [target2] ...",
	Short: "Start scan on multiple targets or CIDR",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		payload := map[string]interface{}{"targets": args}
		fmt.Printf("[*] Starting multi-scan: %v\n", args)
		data, _, err := doRequest("POST", "/scan/multi", payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		prettyPrint(data)
	},
}

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage scheduled scans",
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List schedules",
	Run: func(cmd *cobra.Command, args []string) {
		data, _, err := doRequest("GET", "/schedules", nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		prettyPrint(data)
	},
}

var scheduleAddCmd = &cobra.Command{
	Use:   "add [target] [interval_hours]",
	Short: "Add a scheduled scan",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		var hours int
		fmt.Sscanf(args[1], "%d", &hours)
		payload := map[string]interface{}{
			"target":         args[0],
			"interval_hours": hours,
		}
		data, _, err := doRequest("POST", "/schedules", payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		prettyPrint(data)
	},
}

var scheduleDelCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a schedule",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		data, _, err := doRequest("DELETE", "/schedules/"+args[0], nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		prettyPrint(data)
	},
}

func main() {
	rootCmd.PersistentFlags().StringVar(&apiURL, "url", "http://127.0.0.1:8000", "CYRBER API URL")
	rootCmd.PersistentFlags().StringVar(&username, "user", "admin", "API username")
	rootCmd.PersistentFlags().StringVar(&password, "pass", "cyrber2024", "API password")

	scanCmd.Flags().Bool("agent", false, "Use agent mode (Claude autonomous)")
	listCmd.Flags().Int("limit", 20, "Number of scans to show")

	scheduleCmd.AddCommand(scheduleListCmd, scheduleAddCmd, scheduleDelCmd)
	rootCmd.AddCommand(scanCmd, statusCmd, listCmd, multiCmd, scheduleCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
