// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 honeok <i@honeok.com>

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime"
)

var (
	VersionX   byte   = 1
	VersionY   byte   = 1
	VersionZ   byte   = 0
	Codename          = "Geolocation, Fast and Lightweight."
	Intro             = "A lightweight API IP lookup service."
)

func Version() string {
	return fmt.Sprintf("%d.%d.%d", VersionX, VersionY, VersionZ)
}

func PrintBanner() {
	log.Printf("Geolocation %s (%s) (%s %s/%s)",
		Version(),
		Codename,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)
	log.Println(Intro)
}

type ApiResponse struct {
	Success bool             `json:"success"`
	IP      string           `json:"ip"`
	MtGeo   *MeituanGeoData  `json:"mt_geo,omitempty"`
	IPSB    *IpSbGeoData     `json:"ipsb"`
}

type MeituanGeoData struct {
	Lat      float64 `json:"lat"`
	Lng      float64 `json:"lng"`
	Country  string  `json:"country"`
	Province string  `json:"province"`
	City     string  `json:"city"`
	District string  `json:"district"`
	Detail   string  `json:"detail"`
}

type IpSbGeoData struct {
	ISP             string  `json:"isp"`
	Organization    string  `json:"organization"`
	ASN             string  `json:"asn"`
	ASNOrganization string  `json:"asn_organization"`
	Country         string  `json:"country"`
	CountryCode     string  `json:"country_code"`
	Region          string  `json:"region"`
	RegionCode      string  `json:"region_code"`
	City            string  `json:"city"`
	Latitude        float64 `json:"latitude"`
	Longitude       float64 `json:"longitude"`
}

// FetchJsonFromApi fetches JSON from API and unmarshals it
func fetchJsonFromApi(apiUrl string, target interface{}) error {
	httpResponse, err := http.Get(apiUrl)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()

	bodyBytes, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(bodyBytes, target)
}

// Health endpoint
func healthHandler(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.Write([]byte(`{"status":"ok"}`))
}

func rootRequestHandler(responseWriter http.ResponseWriter, request *http.Request) {
	// Serve frontend page on GET
	if request.Method != "POST" {
		http.ServeFile(responseWriter, request, "index.html")
		return
	}

	request.ParseForm()
	queriedIP := request.FormValue("ip")
	if queriedIP == "" {
		json.NewEncoder(responseWriter).Encode(ApiResponse{Success: false})
		return
	}

	// Safe string getter
	safeString := func(m map[string]interface{}, key string) string {
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}

	// Safe float getter
	safeFloat := func(m map[string]interface{}, key string) float64 {
		if v, ok := m[key].(float64); ok {
			return v
		}
		return 0
	}

	// Concurrent channels
	mtChan := make(chan *MeituanGeoData)
	ipsbChan := make(chan *IpSbGeoData)

	// Fetch Meituan concurrently
	go func() {
		meituanApiUrl := "https://apimobile.meituan.com/locate/v2/ip/loc?rgeo=true&ip=" + url.QueryEscape(queriedIP)

		var meituanRawResponse map[string]interface{}
		meituanGeoData := (*MeituanGeoData)(nil)

		if err := fetchJsonFromApi(meituanApiUrl, &meituanRawResponse); err == nil {

			data, ok := meituanRawResponse["data"].(map[string]interface{})
			if ok {

				rgeo, _ := data["rgeo"].(map[string]interface{})
				latitude := safeFloat(data, "lat")
				longitude := safeFloat(data, "lng")

				meituanDetail := ""

				if latitude != 0 || longitude != 0 {
					meituanCityApiUrl := fmt.Sprintf(
						"https://apimobile.meituan.com/group/v1/city/latlng/%f,%f?tag=0",
						latitude, longitude,
					)

					var meituanCityRawResponse map[string]interface{}
					if fetchJsonFromApi(meituanCityApiUrl, &meituanCityRawResponse) == nil {
						if dm, ok := meituanCityRawResponse["data"].(map[string]interface{}); ok {
							if v, ok := dm["detail"].(string); ok {
								meituanDetail = v
							}
						}
					}
				}

				meituanGeoData = &MeituanGeoData{
					Lat:      latitude,
					Lng:      longitude,
					Country:  safeString(rgeo, "country"),
					Province: safeString(rgeo, "province"),
					City:     safeString(rgeo, "city"),
					District: safeString(rgeo, "district"),
					Detail:   meituanDetail,
				}
			}
		}

		mtChan <- meituanGeoData
	}()

	// Fetch IP.SB concurrently
	go func() {
		ipSbApiUrl := "https://api.ip.sb/geoip/" + url.QueryEscape(queriedIP)

		var ipSbRawResponse map[string]interface{}
		ipSbGeoData := &IpSbGeoData{}

		if fetchJsonFromApi(ipSbApiUrl, &ipSbRawResponse) == nil {

			ipSbGeoData.ISP = safeString(ipSbRawResponse, "isp")
			ipSbGeoData.Organization = safeString(ipSbRawResponse, "organization")
			ipSbGeoData.ASNOrganization = safeString(ipSbRawResponse, "asn_organization")
			ipSbGeoData.Country = safeString(ipSbRawResponse, "country")
			ipSbGeoData.CountryCode = safeString(ipSbRawResponse, "country_code")
			ipSbGeoData.Region = safeString(ipSbRawResponse, "region")
			ipSbGeoData.RegionCode = safeString(ipSbRawResponse, "region_code")
			ipSbGeoData.City = safeString(ipSbRawResponse, "city")

			switch v := ipSbRawResponse["asn"].(type) {
			case string:
				ipSbGeoData.ASN = v
			case float64:
				ipSbGeoData.ASN = fmt.Sprintf("%.0f", v)
			case json.Number:
				ipSbGeoData.ASN = v.String()
			}

			if lat, ok := ipSbRawResponse["latitude"].(float64); ok {
				ipSbGeoData.Latitude = lat
			}
			if lng, ok := ipSbRawResponse["longitude"].(float64); ok {
				ipSbGeoData.Longitude = lng
			}
		}

		ipsbChan <- ipSbGeoData
	}()

	meituanGeoData := <-mtChan
	ipSbGeoData := <-ipsbChan

	finalResponse := ApiResponse{
		Success: true,
		IP:      queriedIP,
		MtGeo:   meituanGeoData,
		IPSB:    ipSbGeoData,
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(finalResponse)
}

func main() {
	PrintBanner()

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", rootRequestHandler)

	// Start HTTP server
	log.Fatal(http.ListenAndServe(":8080", nil))
}
