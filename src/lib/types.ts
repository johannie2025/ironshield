export type Severity = "info" | "warning" | "critical";

export interface Alert {
  id: number;
  title: string;
  description: string;
  severity: Severity;
  acknowledged: 0 | 1;
  created_at: string;
}

export interface AlertsResponse {
  alerts: Alert[];
}
