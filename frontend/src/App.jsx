import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts";

import "./App.css";
import Login from "./Login";

const API = "http://127.0.0.1:5000";

const api = axios.create({
  baseURL: API,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  return config;
});

function App() {

  const [loggedIn, setLoggedIn] = useState(
    localStorage.getItem("loggedIn") === "true"
  );

  const [statistics, setStatistics] = useState({
    total_packets: 0,
    total_alerts: 0,
    status: "Connecting...",
    protocol_counts: {
      TCP: 0,
      UDP: 0,
      ICMP: 0,
      Other: 0,
    },
  });

  const [alerts, setAlerts] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [analytics, setAnalytics] = useState({});
  const [location, setLocation] = useState(null);
  const [locationLoading, setLocationLoading] = useState(false);
  const [error, setError] = useState("");

  const [emailConfigured, setEmailConfigured] = useState(false);
  const [emailStatus, setEmailStatus] = useState("");
  const [sendingEmail, setSendingEmail] = useState(false);

  const logout = () => {
    localStorage.removeItem("loggedIn");
    localStorage.removeItem("token");
    setLoggedIn(false);
  };

  const loadDashboard = async () => {

    try {

      const [
        statisticsResponse,
        alertsResponse,
        trafficResponse,
        analyticsResponse,
      ] = await Promise.all([
        api.get("/api/statistics"),
        api.get("/api/alerts"),
        api.get("/api/traffic"),
        api.get("/api/analytics"),
      ]);

      setStatistics(statisticsResponse.data);
      setAlerts(alertsResponse.data);
      setTraffic(trafficResponse.data);
      setAnalytics(analyticsResponse.data);
      setError("");

    } catch (err) {

      console.error(err);

      if (err.response && (err.response.status === 401 || err.response.status === 422)) {
        logout();
      } else {
        setError("Unable to connect to Flask Backend.");
      }
    }
  };

  const loadEmailStatus = async () => {
    try {
      const response = await api.get("/api/notify/status");
      setEmailConfigured(Boolean(response.data.configured));
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {

    if (loggedIn) {

      loadDashboard();
      loadEmailStatus();

      const interval = setInterval(
        loadDashboard,
        2000
      );

      return () => clearInterval(interval);
    }

  }, [loggedIn]);

  const exportCSV = async () => {
    try {
      const response = await api.get("/api/alerts/export", {
        responseType: "blob",
      });

      const url = window.URL.createObjectURL(response.data);
      const link = document.createElement("a");

      link.href = url;
      link.setAttribute("download", "Smart_NIDS_Alerts.csv");
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      setError("Unable to export alerts.");
    }
  };

  const downloadPDF = async () => {
    try {
      const response = await api.get("/api/report", {
        responseType: "blob",
      });

      const url = window.URL.createObjectURL(response.data);
      const link = document.createElement("a");

      link.href = url;
      link.setAttribute("download", "Security_Report.pdf");
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      setError("Unable to generate report.");
    }
  };

  const getLocation = async (ip) => {

    setLocationLoading(true);

    try {

      const response = await api.get(`/api/location/${ip}`);

      setLocation({ ip, ...response.data });

    } catch {

      setError("Unable to fetch location.");

    } finally {

      setLocationLoading(false);

    }

  };

  const sendTestEmail = async () => {

    setSendingEmail(true);
    setEmailStatus("");

    try {

      const response = await api.post("/api/notify/test", {
        source_ip: alerts[0]?.source_ip || "0.0.0.0",
        attack_type: alerts[0]?.type || "Test Alert",
      });

      setEmailStatus(response.data.message);

    } catch (err) {

      setEmailStatus(
        err.response?.data?.message || "Unable to send test email."
      );

    } finally {

      setSendingEmail(false);

    }

  };

  const protocolData = useMemo(() => {

    const counts =
      statistics.protocol_counts || {};

    return [
      {
        name: "TCP",
        value: counts.TCP || 0,
      },
      {
        name: "UDP",
        value: counts.UDP || 0,
      },
      {
        name: "ICMP",
        value: counts.ICMP || 0,
      },
      {
        name: "Other",
        value: counts.Other || 0,
      },
    ];

  }, [statistics]);

  const trafficData = useMemo(
    () =>
      traffic
        .slice(0, 20)
        .reverse()
        .map((packet, index) => ({
          id: index + 1,
          packets: index + 1,
        })),
    [traffic]
  );

  const attackChart = useMemo(
    () =>
      Object.entries(analytics.attack_types || {}).map(
        ([name, value]) => ({ name, value })
      ),
    [analytics]
  );

  if (!loggedIn) {

    return (
      <Login
        onLogin={() => setLoggedIn(true)}
      />
    );

  }

  return (
    <div className="container">

      <header>

        <div>
          <h1>
            Smart Network Intrusion Detection System
          </h1>

          <p>
            Flask + React + Scapy Dashboard
          </p>
        </div>

        <div
          style={{
            display: "flex",
            gap: "10px",
            alignItems: "center",
          }}
        >

          <button
            className="export-button"
            onClick={downloadPDF}
          >
            PDF Report
          </button>

          <button
            className="export-button"
            onClick={exportCSV}
          >
            Export CSV
          </button>

          <button
            className="logout-button"
            onClick={logout}
          >
            Logout
          </button>

        </div>

      </header>

      {error && (
        <div className="error">
          {error}
        </div>
      )}

      <section className="cards">

        <div className="card">
          <h3>Total Packets</h3>
          <h2>{statistics.total_packets}</h2>
        </div>

        <div className="card">
          <h3>Total Alerts</h3>
          <h2>{statistics.total_alerts}</h2>
        </div>

        <div className="card">
          <h3>TCP</h3>
          <h2>
            {statistics.protocol_counts?.TCP || 0}
          </h2>
        </div>

        <div className="card">
          <h3>UDP</h3>
          <h2>
            {statistics.protocol_counts?.UDP || 0}
          </h2>
        </div>

      </section>

      <section className="card">

        <h2>Email Notifications</h2>

        <p>
          Status:{" "}
          <b>
            {emailConfigured ? "Configured" : "Not configured"}
          </b>
        </p>

        <button
          className="export-button"
          onClick={sendTestEmail}
          disabled={sendingEmail || !emailConfigured}
        >
          {sendingEmail ? "Sending..." : "Send Test Alert Email"}
        </button>

        {!emailConfigured && (
          <p style={{ marginTop: "8px" }}>
            Set SENDER_EMAIL / SENDER_PASSWORD in app.py to enable this.
          </p>
        )}

        {emailStatus && (
          <p style={{ marginTop: "8px" }}>{emailStatus}</p>
        )}

      </section>

      <section className="graphs">

        <div className="graph">

          <h2>Live Traffic</h2>

          <ResponsiveContainer
            width="100%"
            height={300}
          >
            <AreaChart data={trafficData}>

              <CartesianGrid strokeDasharray="3 3" />

              <XAxis dataKey="id" />

              <YAxis />

              <Tooltip />

              <Area
                type="monotone"
                dataKey="packets"
                stroke="#00bcd4"
                fill="#00bcd4"
              />

            </AreaChart>
          </ResponsiveContainer>

        </div>

        <div className="graph">

          <h2>Protocol Distribution</h2>

          <ResponsiveContainer
            width="100%"
            height={300}
          >

            <PieChart>

              <Pie
                data={protocolData}
                dataKey="value"
                nameKey="name"
                outerRadius={100}
              >

                <Cell fill="#00bcd4" />
                <Cell fill="#8e44ad" />
                <Cell fill="#22c55e" />
                <Cell fill="#f39c12" />

              </Pie>

              <Tooltip />

            </PieChart>

          </ResponsiveContainer>

        </div>

      </section>

      <section className="graph">

        <h2>
          Attack Analysis
        </h2>

        <ResponsiveContainer
          width="100%"
          height={350}
        >

          <BarChart
            data={attackChart}
          >

            <CartesianGrid
              strokeDasharray="3 3"
            />

            <XAxis
              dataKey="name"
            />

            <YAxis />

            <Tooltip />

            <Bar
              dataKey="value"
              fill="#ef4444"
            />

          </BarChart>

        </ResponsiveContainer>

      </section>

      {location && (

        <div className="location-popup-overlay" onClick={() => setLocation(null)}>

          <div
            className="location-popup"
            onClick={(e) => e.stopPropagation()}
          >

            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <h2>IP Geolocation — {location.ip}</h2>
              <button onClick={() => setLocation(null)}>✕</button>
            </div>

            <p><b>Country:</b> {location.country}</p>
            <p><b>Region:</b> {location.regionName}</p>
            <p><b>City:</b> {location.city}</p>
            <p><b>ISP:</b> {location.isp}</p>
            <p><b>Latitude:</b> {location.lat}</p>
            <p><b>Longitude:</b> {location.lon}</p>

          </div>

        </div>

      )}

      <section className="table">

        <h2>
          Recent Security Alerts
        </h2>

        <table>

          <thead>

            <tr>
              <th>Time</th>
              <th>Attack</th>
              <th>Source IP</th>
              <th>Severity</th>
              <th>Location</th>
            </tr>

          </thead>

          <tbody>

            {alerts.length === 0 ? (

              <tr>
                <td colSpan="5" style={{ textAlign: "center" }}>
                  No Alerts
                </td>
              </tr>

            ) : (

              alerts.map(
                (alert, index) => (

                <tr key={index}>

                  <td>
                    {alert.timestamp}
                  </td>

                  <td>
                    {alert.type}
                  </td>

                  <td>
                    {alert.source_ip}
                  </td>

                  <td>
                    {alert.severity}
                  </td>

                  <td>

                    <button
                      onClick={() =>
                        getLocation(
                          alert.source_ip
                        )
                      }
                      disabled={locationLoading}
                    >
                      Locate
                    </button>

                  </td>

                </tr>

              ))

            )}

          </tbody>

        </table>

      </section>

      <section className="table">

        <h2>
          Live Network Traffic
        </h2>

        <table>

          <thead>

            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Port</th>
              <th>Protocol</th>
            </tr>

          </thead>

          <tbody>

            {traffic.length === 0 ? (

              <tr>
                <td colSpan="5" style={{ textAlign: "center" }}>
                  Waiting for packets...
                </td>
              </tr>

            ) : (

              traffic
                .slice(0, 20)
                .map((packet, index) => (

                <tr key={index}>

                  <td>
                    {packet.timestamp}
                  </td>

                  <td>
                    {packet.source_ip}
                  </td>

                  <td>
                    {packet.destination_ip}
                  </td>

                  <td>
                    {packet.destination_port}
                  </td>

                  <td>
                    {packet.protocol}
                  </td>

                </tr>

              ))

            )}

          </tbody>

        </table>

      </section>

      <footer>

        <b>
          Developed by Sinchana T R
        </b>

      </footer>

    </div>
  );
}

export default App;