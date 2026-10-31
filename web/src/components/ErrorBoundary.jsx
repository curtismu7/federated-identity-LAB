import { Component } from "react";

// A render guard: if any tab throws while rendering (for example, a lookup against data that is still for the previous vertical), the page shows a short message
// and a way back instead of going blank. The parent changes `resetKey` when the vertical or mode changes, which remounts the guard and clears the error.
export default class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { failed: false, n: 0 }; }
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch() { /* nothing is logged with the visitor's data; the message below is all the page keeps */ }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="panel" role="alert" data-testid="render-error" data-state="bad">
        <p><strong>This view could not be drawn.</strong> The lab is still running and your state is safe on the server.</p>
        <p><button type="button" onClick={() => this.setState({ failed: false, n: this.state.n + 1 })} data-testid="render-retry">Draw it again</button></p>
      </div>
    );
  }
}
