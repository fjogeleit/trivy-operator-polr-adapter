package shared

type LabelMapper struct {
	applyLabels []string
}

func (m *LabelMapper) CreateLabels(labels map[string]string, defaultLabels map[string]string) map[string]string {
	l := map[string]string{}
	for key, value := range defaultLabels {
		l[key] = value
	}

	for _, key := range m.applyLabels {
		if value, ok := labels[key]; ok {
			l[key] = value
		}
	}

	return l
}

func NewLabelMapper(applyLabels []string) LabelMapper {
	return LabelMapper{applyLabels}
}
