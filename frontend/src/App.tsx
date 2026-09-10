import {useEffect, useState} from "react";
import {getDashboardStats, getAlerts} from "./api/api";
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer
} from "recharts";
import StatCard from "./components/StatCard";
import AlertTable from "./components/AlertTable";

type DashboardStats={
  total_events:number;
  total_alerts:number;
  alerts_by_status:{
    open:number;
    investigating:number;
    resolved:number;
  };
  alerts_by_severity:{
    critical:number;
    high:number;
    medium:number;
    low:number;
  };
  alerts_by_threat_type:{
    [key: string]:number;
  };
};

type Alert={
  id:number;
  threat_type:string;
  severity:string;
  risk_score:number;
  source_ip:string;
  username: string | null;
  message:string;
  status:string;
  created_at:string;
};

function App(){
  const [stats,setStats]=useState<DashboardStats | null>(null);
  const [alerts,setAlerts]=useState<Alert[]>([]);
  const [error,setError]=useState<string | null>(null);
    useEffect(()=>{
    async function loadDashboard(){
      try{
        const statsData=await getDashboardStats();
        const alertsData=await getAlerts();
        setStats(statsData);
        setAlerts(alertsData);
      } catch(err){
        setError("Unable to load dashboard statistics.");
      }
    }
    loadDashboard();
    const ws = new WebSocket("ws://127.0.0.1:8000/ws/alerts");
    ws.onmessage = async (event) => {
      const newAlert = JSON.parse(event.data);
      setAlerts((currentAlerts) => [newAlert, ...currentAlerts]);
      try {
        const latestStats = await getDashboardStats();
        setStats(latestStats);
      } catch (error) {
        console.error("Failed to refresh dashboard statistics:", error);
      }
    };
    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
    };
    return () => {
      ws.close();
    };
  }, []); // Empty dependency array means this effect runs once on component mount

  if (error){
    return <h2>{error}</h2>;
  }

  if (!stats){
    return <h2>Loading SentinelSOC...</h2>;
  }
  const severityData=[
    {
      severity: "Critical",
      count: stats.alerts_by_severity.critical,
    },
    {
      severity: "High",
      count: stats.alerts_by_severity.high,
    },
    {
      severity: "Medium",
      count: stats.alerts_by_severity.medium,
    },
    {
      severity: "Low",
      count: stats.alerts_by_severity.low
    },
  ];
  const threatTypeData=Object.entries(
    stats.alerts_by_threat_type
  ).map(([threat, count])=>({
    threat,
    count,
  }));
  return(
    <div className="dashboard">
      <header className="dashboard-header">
      <div>
      <h1>SentinelSOC</h1>
      <p>
        Security Operations Center
      </p>
      </div>
      </header>
      <section className="stats-grid">
        <StatCard
          title="Total Events"
          value={stats.total_events}
          icon={Activity}
        />
        <StatCard
          title="Total Alerts"
          value={stats.total_alerts}
          icon={ShieldAlert}
        />
        <StatCard
          title="Open Alerts"
          value={stats.alerts_by_status.open}
          icon={AlertTriangle}  
        />
        <StatCard
          title="High Alerts"
          value={stats.alerts_by_severity.high}
          icon={ShieldCheck}
        />
      </section>
      <section className="severity-section">
        <h2>Alerts by Severity</h2>
        <div className="severity-list">
          <p>Critical: {stats.alerts_by_severity.critical}</p>
          <p>High: {stats.alerts_by_severity.high}</p>
          <p>Medium: {stats.alerts_by_severity.medium}</p>
          <p>Low: {stats.alerts_by_severity.low}</p>
        </div>
      </section>
      <section className="chart-section">
        <h2>Severity Distribution</h2>
        <div className="chart-container">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severityData}>
              <XAxis dataKey="severity" tick={{ fill: "#94a3b8"}}/>
              <YAxis allowDecimals={false} tick={{fill:"#94a3b8"}}/>
              <Tooltip formatter={(value)=>[`${value}`,"Alerts"]}/>
              <Bar dataKey="count" fill="#ef4444"/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
      <section className="chart-section">
        <h2>Threat Type Distribution</h2>
        <div className="chart-container">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={threatTypeData}>
              <XAxis dataKey="threat" tick={{fill:"#94a3b8"}}/>
              <YAxis allowDecimals={false} tick={{fill:"#94a3b8"}}/>
              <Tooltip formatter={(value)=>[`${value}`,"Alerts"]}/>
              <Bar dataKey="count" fill="#f97316"/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
      <AlertTable
    alerts={alerts}
    onStatusChange={(alertId, status) => {
    setAlerts((currentAlerts) =>
        currentAlerts.map((alert) =>
            alert.id === alertId
                ? { ...alert, status }
                : alert
        )
    );
    setStats((currentStats) => {
        if (!currentStats) return currentStats;
        const oldAlert = alerts.find(
            (alert) => alert.id === alertId
        );
        if (!oldAlert || oldAlert.status === status) {
            return currentStats;
        }
        const oldStatus = oldAlert.status.toLowerCase();
        const newStatus = status.toLowerCase();
        return {
            ...currentStats,
            alerts_by_status: {
                ...currentStats.alerts_by_status,
                [oldStatus]: currentStats.alerts_by_status[
                    oldStatus as keyof typeof currentStats.alerts_by_status
                ] - 1,
                [newStatus]: currentStats.alerts_by_status[
                    newStatus as keyof typeof currentStats.alerts_by_status
                ] + 1,
            },
        };
    });
    }}
    />
    </div>
  );
}

export default App;