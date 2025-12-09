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
	VersionY   byte   = 0
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
	MtGeo   *MeituanGeoData  `json:"mt_geo"`
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

	// Meituan IP location API
	meituanApiUrl := "https://apimobile.meituan.com/locate/v2/ip/loc?rgeo=true&ip=" + url.QueryEscape(queriedIP)

	var meituanRawResponse map[string]interface{}
	if err := fetchJsonFromApi(meituanApiUrl, &meituanRawResponse); err != nil {
		json.NewEncoder(responseWriter).Encode(ApiResponse{Success: false})
		return
	}

	meituanData := meituanRawResponse["data"].(map[string]interface{})
	meituanReverseGeo := meituanData["rgeo"].(map[string]interface{})
	latitude := meituanData["lat"].(float64)
	longitude := meituanData["lng"].(float64)

	// Meituan city detail API
	meituanCityApiUrl := fmt.Sprintf(
		"https://apimobile.meituan.com/group/v1/city/latlng/%f,%f?tag=0",
		latitude, longitude,
	)

	var meituanCityRawResponse map[string]interface{}
	fetchJsonFromApi(meituanCityApiUrl, &meituanCityRawResponse)

	cityDetail := ""
	if meituanCityRawResponse["data"] != nil {
		if dataMap, ok := meituanCityRawResponse["data"].(map[string]interface{}); ok {
			if val, ok := dataMap["detail"].(string); ok {
				cityDetail = val
			}
		}
	}

	meituanGeoData := &MeituanGeoData{
		Lat:      latitude,
		Lng:      longitude,
		Country:  meituanReverseGeo["country"].(string),
		Province: meituanReverseGeo["province"].(string),
		City:     meituanReverseGeo["city"].(string),
		District: meituanReverseGeo["district"].(string),
		Detail:   cityDetail,
	}

	// IP.SB GeoIP API
	ipSbApiUrl := "https://api.ip.sb/geoip/" + url.QueryEscape(queriedIP)

	var ipSbRawResponse map[string]interface{}
	ipSbGeoData := &IpSbGeoData{}

	if fetchJsonFromApi(ipSbApiUrl, &ipSbRawResponse) == nil {
		ipSbGeoData.ISP, _ = ipSbRawResponse["isp"].(string)
		ipSbGeoData.Organization, _ = ipSbRawResponse["organization"].(string)

		// ASN may be string or number
		rawASN := ipSbRawResponse["asn"]
		switch value := rawASN.(type) {
		case string:
			ipSbGeoData.ASN = value
		case float64:
			ipSbGeoData.ASN = fmt.Sprintf("%.0f", value)
		}

		ipSbGeoData.ASNOrganization, _ = ipSbRawResponse["asn_organization"].(string)
		ipSbGeoData.Country, _ = ipSbRawResponse["country"].(string)
		ipSbGeoData.CountryCode, _ = ipSbRawResponse["country_code"].(string)
		ipSbGeoData.Region, _ = ipSbRawResponse["region"].(string)
		ipSbGeoData.RegionCode, _ = ipSbRawResponse["region_code"].(string)
		ipSbGeoData.City, _ = ipSbRawResponse["city"].(string)

		if lat, ok := ipSbRawResponse["latitude"].(float64); ok {
			ipSbGeoData.Latitude = lat
		}
		if lng, ok := ipSbRawResponse["longitude"].(float64); ok {
			ipSbGeoData.Longitude = lng
		}
	}

	// Final JSON output
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

	http.HandleFunc("/", rootRequestHandler)

	// Start HTTP server
	log.Fatal(http.ListenAndServe(":8080", nil))
}
