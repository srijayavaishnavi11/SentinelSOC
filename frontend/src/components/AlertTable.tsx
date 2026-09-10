import { useState } from "react";
import { updateAlertStatus } from "../api/api";
type Alert={
    id:number;
    threat_type:string;
    severity:string;
    risk_score:number;
    source_ip:string;
    username:string | null;
    message: string;
    status: string;
    created_at: string;
};

type AlertTableProps={
    alerts:Alert[];
    onStatusChange:(alertId:number, status:string)=>void;
};

function AlertTable({alerts, onStatusChange}: AlertTableProps){
    const [selectedAlert, setSelectedAlert]=useState<Alert | null>(null);
    const handleStatusChange = async (
    alertId: number,
    status: string
    ) => {
        try {
            await updateAlertStatus(alertId, status);
            onStatusChange(alertId, status);
        } 
        catch (error) {
            console.error("Failed to update alert status:", error);
        }
    };
    return(
        <div className="alert-section">
            <h2>Recent Security Alerts</h2>
            <div className="alert-table-container">
                <table className="alert-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Threat</th>
                            <th>Source IP</th>
                            <th>Severity</th>
                            <th>Risk</th>
                            <th>Details</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alerts.length===0?(
                            <tr>
                                <td colSpan={8} className="no-alerts">
                                    No security alerts detected
                                </td>
                            </tr>
                        ) : (
                            alerts.map((alert)=>(
                                <tr key={alert.id} onClick={()=>setSelectedAlert(alert)} className="alert-row">
                                    <td>#{alert.id}</td>
                                    <td>{alert.threat_type}</td>
                                    <td>{alert.source_ip}</td>
                                    <td>
                                        <span className={`severity-badge ${alert.severity.toLowerCase()}`}>
                                            {alert.severity}
                                        </span>                                
                                    </td>
                                    <td>
                                        <span className={`risk-badge ${alert.severity.toLocaleLowerCase()}`}>
                                            {alert.risk_score}
                                        </span>
                                    </td>
                                    <td className="alert-message">{alert.message}</td>
                                    <td>
                                        <select
                                            value={alert.status.toLowerCase()} onChange={(event) => 
                                                handleStatusChange(alert.id, event.target.value)
                                            }
                                            className={`status-select ${alert.status.toLowerCase()}`}
                                            onClick={(event) => event.stopPropagation()}
                                        >
                                            <option value="open">Open</option>
                                            <option value="investigating">Investigating</option>
                                            <option value="resolved">Resolved</option>
                                        </select>
                                    </td>
                                    <td>{new Date(alert.created_at).toLocaleString()}</td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            {selectedAlert && (
                <div className="alert-details">
                    <div className="alert-details-header">
                        <h2>Alert Investigation</h2>
                        <button onClick={()=>setSelectedAlert(null)}>
                            Close
                        </button>
                    </div>
                    <div className="alert-details-grid">
                        <p><strong>Alert ID:</strong> #{selectedAlert.id}</p>
                        <p><strong>Threat:</strong> {selectedAlert.threat_type}</p>
                        <p><strong>Source IP:</strong> {selectedAlert.source_ip}</p>
                        <p><strong>Username:</strong> {selectedAlert.username || "N/A"}</p>
                        <p><strong>Severity:</strong> {selectedAlert.severity}</p>
                        <p><strong>Risk Score:</strong> {selectedAlert.risk_score}</p>
                        <p><strong>Status:</strong> {selectedAlert.status}</p>
                        <p><strong>Detected:</strong> {new Date(selectedAlert.created_at).toLocaleString()}</p>
                    </div>
                    <div className="alert-details-message">
                        <strong>Detection Details</strong>
                        <p>{selectedAlert.message}</p>
                    </div>
                </div>
            )}
            </div>
        </div>
    );
}

export default AlertTable;