// The diagram's opening view is chosen from the screen width: at phone width every box is fitted (never just the first two), on a wide screen the usual padding.
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";

let seen = null;
vi.mock("@xyflow/react", async (orig) => {
  const real = await orig();
  return { ...real, ReactFlow: (props) => { seen = props; return null; } };
});
const { default: PatternDiagram, MIN_ZOOM, fitFor } = await import("./components/PatternDiagram");

const pattern = { title: "t", intro: "i", nodes: [{ id: "a", label: "A", kind: "src", x: 0, y: 0 }, { id: "b", label: "B", kind: "ping", x: 500, y: 0 }, { id: "c", label: "C", kind: "rec", x: 1000, y: 300 }], steps: [{ from: "a", to: "b", label: "one", say: "s" }] };
const realMatch = window.matchMedia;
afterEach(() => { cleanup(); seen = null; window.matchMedia = realMatch; });

describe("the diagram's opening view (N4)", () => {
  it("at phone width the view fits every box, with a zoom floor low enough for the whole drawing", () => {
    window.matchMedia = (q) => ({ matches: /max-width: 600px/.test(q), media: q, addEventListener() {}, removeEventListener() {} });
    render(<PatternDiagram pattern={pattern} />);
    expect(seen.fitViewOptions).toEqual(fitFor(true)); expect(seen.fitViewOptions.nodes).toBeUndefined();
    expect(seen.fitViewOptions.minZoom).toBe(MIN_ZOOM); expect(seen.minZoom).toBe(MIN_ZOOM); expect(seen.fitView).toBe(true);
  });
  it("on a wide screen it is the usual padded fit", () => {
    window.matchMedia = (q) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} });
    render(<PatternDiagram pattern={pattern} />);
    expect(seen.fitViewOptions).toEqual(fitFor(false)); expect(seen.fitViewOptions.padding).toBe(0.08); expect(seen.minZoom).toBe(MIN_ZOOM);
  });
});
