package encoding

func BoolToHealthString(healthy bool) string {
	if healthy {
		return "healthy"
	}

	return "unhealthy"
}
