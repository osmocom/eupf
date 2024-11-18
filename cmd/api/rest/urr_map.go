package rest

import (
	"github.com/edgecomllc/eupf/cmd/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"net/http"
	"strconv"
	"unsafe"
)

// ListUrrMapContent godoc
//	@Summary		List URR map content
//	@Description	List URR map content
//	@Tags			URR
//	@Produce		json
//	@Success		200	{object}	[]ebpf.UrrMapElement
//	@Router			/urr_map [get]
func (h *ApiHandler) listUrrMapContent(c *gin.Context) {
	if elements, err := ebpf.ListUrrMapContents(h.BpfObjects.IpEntrypointObjects.UrrInfoMap, h.BpfObjects.IpEntrypointObjects.UrrAccMap); err != nil {
		log.Info().Msgf("Error reading map: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	} else {
		c.IndentedJSON(http.StatusOK, elements)
	}
}

// GetUrrValue godoc
//	@Summary		List URR map content
//	@Description	List URR map content
//	@Tags			URR
//	@Produce		json
//	@Param			id	path		int	true	"Urr ID"
//	@Success		200	{object}	[]ebpf.UrrMapElement
//	@Router			/urr_map/{id} [get]
func (h *ApiHandler) getUrrValue(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		log.Info().Msgf("Error converting id to int: %s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var info ebpf.UrrInfo
	var acc  ebpf.UrrAcc

	err = h.BpfObjects.IpEntrypointObjects.UrrInfoMap.Lookup(uint32(id), unsafe.Pointer(&info))
	if err == nil {
		err = h.BpfObjects.IpEntrypointObjects.UrrAccMap.Lookup(uint32(id), unsafe.Pointer(&acc))
	}
	if err != nil {
		log.Printf("Error reading map: %s", err.Error())
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, ebpf.UrrMapElement{
		Id:           uint32(id),
		MeasMethod:	info.MeasMethod,
		MeasInfo:	info.MeasInfo,
		ReportTrigger:  (uint32(info.RepTri5)<<16) |
			(uint32(info.RepTri6)<<8) |
			(uint32(info.RepTri7)),
		VolumeThresholdFlags:	info.VolThresholdFlags,
		VolumeThresholdTotal:	info.VolThresholdTotal,
		VolumeThresholdUplink:	info.VolThresholdUplink,
		VolumeThresholdDownlink:info.VolThresholdDownlink,
		VolumeQuotaFlags:	info.VolQuotaFlags,
		VolumeQuotaTotal:	info.VolQuotaTotal,
		VolumeQuotaUplink:	info.VolQuotaUplink,
		VolumeQuotaDownlink:	info.VolQuotaDownlink,
		TotalOctets:		acc.TotalOctets,
		UplinkOctets:		acc.UlOctets,
		DownlinkOctets:		acc.DlOctets,
		TotalPackets:		acc.TotalPkts,
		UplinkPackets:		acc.UlPkts,
		DownlinkPackets:	acc.DlPkts,
	})
}

func (h *ApiHandler) setUrrValue(c *gin.Context) {
	var urrElement ebpf.UrrMapElement
	if err := c.BindJSON(&urrElement); err != nil {
		log.Printf("Parsing request body error: %s", err.Error())
		return
	}

	var info = ebpf.UrrInfo{
		MeasMethod:	urrElement.MeasMethod,
		RepTri5:	uint8((urrElement.ReportTrigger >> 16) & 0xFF),
		RepTri6:	uint8((urrElement.ReportTrigger >> 8 ) & 0xFF),
		RepTri7:	uint8((urrElement.ReportTrigger      ) & 0xFF),
		MeasInfo:	urrElement.MeasInfo,
		VolThresholdFlags:	urrElement.VolumeThresholdFlags,
		VolThresholdTotal: 	urrElement.VolumeThresholdUplink,
		VolThresholdUplink: 	urrElement.VolumeThresholdDownlink,
		VolThresholdDownlink:	urrElement.VolumeThresholdTotal,
		VolQuotaFlags:		urrElement.VolumeQuotaFlags,
		VolQuotaTotal:		urrElement.VolumeQuotaTotal,
		VolQuotaUplink:		urrElement.VolumeQuotaUplink,
		VolQuotaDownlink:	urrElement.VolumeQuotaDownlink,
	}

	if err := h.BpfObjects.IpEntrypointObjects.UrrInfoMap.Put(uint32(urrElement.Id), unsafe.Pointer(&info)); err != nil {
		log.Printf("Error writting map: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.IndentedJSON(http.StatusCreated, urrElement)
}
